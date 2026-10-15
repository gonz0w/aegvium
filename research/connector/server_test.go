// SPDX-License-Identifier: BSD-3-Clause
package comparison

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
)

func serverEmit(v any) { b, _ := json.Marshal(v); fmt.Println("SERVER " + string(b)) }

// A child sets XDG directories before Caddy's package initialization, isolating
// process-global configuration, pools and default storage from the API controls.
func TestConfiguredCaddyTLS(t *testing.T) {
	if os.Getenv("AEGVIUM_CADDY_CHILD") == "owned-fixture" {
		configuredCaddyChild(t)
		return
	}
	root, err := os.MkdirTemp("", "aegvium-configured-caddy-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, exe, "-test.v", "-test.timeout=110s", "-test.run=^TestConfiguredCaddyTLS$")
	cmd.Env = []string{"PATH=/usr/bin:/bin", "AEGVIUM_CADDY_CHILD=owned-fixture", "AEGVIUM_CADDY_ROOT=" + root, "XDG_CONFIG_HOME=" + filepath.Join(root, "config"), "XDG_DATA_HOME=" + filepath.Join(root, "data"), "NO_PROXY=*", "GOTELEMETRY=off"}
	if os.Getenv("AEGVIUM_CONNECTOR_REPEAT") == "owned-guest" {
		cmd.Env = append(cmd.Env, "AEGVIUM_CONNECTOR_REPEAT=owned-guest")
	}
	output, runErr := cmd.CombinedOutput()
	if dir := os.Getenv("AEGVIUM_CADDY_LOG_DIR"); dir != "" {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		file, err := os.CreateTemp(dir, "configured-*.log")
		if err != nil {
			t.Fatal(err)
		}
		if _, err = file.Write(output); err != nil {
			t.Fatal(err)
		}
		if err = file.Close(); err != nil {
			t.Fatal(err)
		}
	}
	for _, line := range strings.Split(string(output), "\n") {
		if strings.HasPrefix(line, "SERVER ") {
			fmt.Println(line)
		}
	}
	if runErr != nil {
		t.Fatalf("configured child failed: %v; ignored raw log sha256 %s", runErr, hash(output))
	}
	if err := os.RemoveAll(root); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatal("owned assets remain")
	}
	serverEmit(map[string]any{"kind": "process-cleanup", "child_exited": true, "assets_removed": true, "raw_log_sha256": hash(output)})
}

type serverEffect struct {
	body, authority string
	clean           bool
}
type serverObservation struct {
	Kind        string `json:"kind"`
	Case        string `json:"case"`
	Status      int    `json:"status"`
	Backend     int    `json:"backend"`
	Body        string `json:"body_sha256"`
	Authority   string `json:"authority"`
	Clean       bool   `json:"headers_clean"`
	ClientError bool   `json:"client_error"`
	Leaked      bool   `json:"response_leaked"`
	Input       string `json:"input_sha256"`
	SNI         string `json:"sni"`
	Host        string `json:"http_host"`
}

func configuredCaddyChild(t *testing.T) {
	root := os.Getenv("AEGVIUM_CADDY_ROOT")
	if root == "" || os.Getenv("XDG_CONFIG_HOME") != filepath.Join(root, "config") || os.Getenv("XDG_DATA_HOME") != filepath.Join(root, "data") {
		t.Fatal("owned child paths required")
	}
	makeKey := func() *ecdsa.PrivateKey {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return key
	}
	caKey := makeKey()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "owned fixture CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leaf := func(serial int64, names []string, untrusted bool) (tls.Certificate, []byte, []byte) {
		key := makeKey()
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), DNSNames: names, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		issuer, signing := ca, caKey
		if untrusted {
			issuer, signing = template, key
		}
		der, err := x509.CreateCertificate(rand.Reader, template, issuer, &key.PublicKey, signing)
		if err != nil {
			t.Fatal(err)
		}
		keyDER, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		certPEM, keyPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
		cert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			t.Fatal(err)
		}
		return cert, certPEM, keyPEM
	}
	_, certPEM, keyPEM := leaf(2, []string{"app.test", "api.test", "alt.test"}, false)
	valid, _, _ := leaf(3, []string{"api.test"}, false)
	wrong, _, _ := leaf(4, []string{"wrong.test"}, false)
	untrusted, _, _ := leaf(5, []string{"api.test"}, true)
	write := func(name string, data []byte) string {
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	certFile, keyFile, caFile := write("leaf.pem", certPEM), write("leaf.key", keyPEM), write("ca.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	var mu sync.Mutex
	var effects []serverEffect
	var certMode atomic.Int32
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(io.LimitReader(r.Body, 4097))
		if err != nil {
			http.Error(w, "read failed", 500)
			return
		}
		clean := true
		for key := range r.Header {
			lower := strings.ToLower(key)
			if lower == "forwarded" || strings.HasPrefix(lower, "x-forwarded-") || lower == "x-real-ip" || lower == "x-original-url" || lower == "x-rewrite-url" || strings.HasPrefix(lower, "proxy-") {
				clean = false
			}
		}
		mu.Lock()
		effects = append(effects, serverEffect{string(data), r.Host, clean})
		mu.Unlock()
		w.Header().Set("Content-Type", "text/plain")
		if r.URL.Path == "/response-header" {
			w.Header().Set("X-Lab-Response", "blocked")
		}
		if r.URL.Path == "/response-body" {
			io.WriteString(w, "aegvium-leak")
			return
		}
		io.WriteString(w, "lab backend\n")
	})
	type ownedBackend struct {
		server *http.Server
		done   chan error
		addr   string
	}
	startBackend := func(addr string, secure bool) *ownedBackend {
		listener, err := net.Listen("tcp4", addr)
		if err != nil {
			t.Fatal(err)
		}
		s := &http.Server{Handler: handler, ReadHeaderTimeout: time.Second, ErrorLog: log.New(io.Discard, "", 0)}
		ln := listener
		if secure {
			ln = tls.NewListener(listener, &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
				switch certMode.Load() {
				case 1:
					return &wrong, nil
				case 2:
					return &untrusted, nil
				}
				return &valid, nil
			}})
		}
		b := &ownedBackend{s, make(chan error, 1), listener.Addr().String()}
		go func() { b.done <- s.Serve(ln) }()
		return b
	}
	stopBackend := func(b *ownedBackend) {
		if b == nil {
			return
		}
		if err := b.server.Close(); err != nil {
			t.Error(err)
		}
		select {
		case err := <-b.done:
			if !errors.Is(err, http.ErrServerClosed) {
				t.Error(err)
			}
		case <-time.After(time.Second):
			t.Error("backend not joined")
		}
	}
	plain, secure := startBackend("127.0.0.1:0", false), startBackend("127.0.0.1:0", true)
	defer func() { stopBackend(plain); stopBackend(secure) }()
	reservation, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listen := reservation.Addr().String()
	reservation.Close()
	config := serverFixtureConfig{listen: listen, plain: plain.addr, secure: secure.addr, cert: certFile, key: keyFile, ca: caFile, storage: filepath.Join(root, "storage"), apiHost: "api.test"}
	if err := loadConfiguredServer(config); err != nil {
		t.Fatal(err)
	}
	defer caddy.Stop()
	configReceipt := func(phase string) {
		raw, err := configuredServer(config)
		if err != nil {
			t.Fatal(err)
		}
		serverEmit(map[string]any{"kind": "config", "phase": phase, "sha256": hash(raw), "strict": config.strict})
	}
	configReceipt("initial")
	request := func(name, method, path, host, sni, body string, headers http.Header, wantStatus, wantBackend int, trust bool) {
		t.Run(name, func(t *testing.T) {
			roots := pool
			if !trust {
				roots = x509.NewCertPool()
			}
			tr := &http.Transport{Proxy: nil, DisableKeepAlives: true, TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: sni, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}}
			defer tr.CloseIdleConnections()
			client := &http.Client{Transport: tr, Timeout: 4 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			r, err := http.NewRequest(method, "https://"+listen+path, strings.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			r.Host = host
			r.Header.Set("User-Agent", "Aegvium owned lab")
			r.Header.Set("Accept", "*/*")
			if method == "POST" {
				r.Header.Set("Content-Type", "application/json")
			}
			for k, v := range headers {
				r.Header[k] = v
			}
			mu.Lock()
			before := len(effects)
			mu.Unlock()
			response, err := client.Do(r)
			o := serverObservation{Kind: "case", Case: name, Clean: true, ClientError: err != nil}
			logical, _ := json.Marshal(map[string]any{"method": method, "path": path, "host": r.Host, "sni": tr.TLSClientConfig.ServerName, "headers": r.Header, "body": body})
			o.Input, o.SNI, o.Host = hash(logical), tr.TLSClientConfig.ServerName, r.Host
			var data []byte
			if err == nil {
				o.Status = response.StatusCode
				data, err = io.ReadAll(io.LimitReader(response.Body, 8193))
				response.Body.Close()
				if err != nil || len(data) > 8192 {
					t.Fatal("response read bound")
				}
				if response.ProtoMajor != 1 || response.ProtoMinor != 1 || response.TLS == nil || (response.TLS.NegotiatedProtocol != "" && response.TLS.NegotiatedProtocol != "http/1.1") {
					t.Fatal("unexpected HTTP/TLS protocol")
				}
			}
			mu.Lock()
			o.Backend = len(effects) - before
			if o.Backend == 1 {
				o.Body = hash([]byte(effects[before].body))
				o.Authority = effects[before].authority
				o.Clean = effects[before].clean
				if effects[before].body != body {
					t.Error("backend body changed")
				}
			}
			mu.Unlock()
			o.Leaked = strings.Contains(string(data), "aegvium-leak")
			serverEmit(o)
			if o.Status != wantStatus || o.Backend != wantBackend || !o.Clean || o.ClientError != (wantStatus == 0) || (wantStatus == 406 && o.Leaked) {
				t.Errorf("unexpected configured server outcome: %+v", o)
			}
			if o.Backend == 1 {
				authority := "app.test"
				if strings.HasPrefix(name, "api-") || strings.HasPrefix(name, "alt-") || name == "strict-matched-api" {
					authority = config.apiHost
				}
				if o.Authority != authority {
					t.Error("backend authority changed")
				}
			}
		})
	}
	get := func(name, host string, code, effect int) {
		request(name, "GET", "/ok", host, "app.test", "", nil, code, effect, true)
	}
	get("get", "app.test", 200, 1)
	request("json", "POST", "/body", "app.test", "app.test", `{"payload":"ordinary"}`, nil, 200, 1, true)
	request("sql", "GET", "/?payload=%27+OR+1%3D1--", "app.test", "app.test", "", nil, 403, 0, true)
	request("script", "POST", "/body", "app.test", "app.test", `{"payload":"<script>alert(1)</script>"}`, nil, 403, 0, true)
	request("oversize", "POST", "/body", "app.test", "app.test", strings.Repeat("x", 4097), nil, 413, 0, true)
	request("media", "POST", "/body", "app.test", "app.test", "ordinary", http.Header{"Content-Type": {"text/plain"}}, 403, 0, true)
	request("upgrade", "GET", "/ok", "app.test", "app.test", "", http.Header{"Connection": {"Upgrade"}, "Upgrade": {"websocket"}}, 501, 0, true)
	get("unknown", "other.test", 421, 0)
	request("spoof", "GET", "/ok", "app.test", "app.test", "", http.Header{"Forwarded": {"for=192.0.2.99"}, "X-Forwarded-For": {"192.0.2.99"}, "X-Real-IP": {"192.0.2.99"}, "X-Original-Url": {"/hidden"}, "Proxy-Authorization": {"synthetic"}}, 200, 1, true)
	request("response-header", "GET", "/response-header", "app.test", "app.test", "", nil, 406, 1, true)
	request("response-body", "GET", "/response-body", "app.test", "app.test", "", nil, 406, 1, true)
	request("untrusted-cert", "GET", "/ok", "app.test", "app.test", "", nil, 0, 0, false)
	request("wrong-name", "GET", "/ok", "app.test", "wrong.test", "", nil, 0, 0, true)
	get("api-get", "api.test", 200, 1)
	request("api-json", "POST", "/body", "api.test", "app.test", `{"payload":"ordinary"}`, nil, 200, 1, true)
	get("api-wrong-port", "api.test:18087", 200, 1)
	certMode.Store(1)
	get("api-wrong-cert", "api.test", 502, 0)
	certMode.Store(2)
	get("api-untrusted-cert", "api.test", 502, 0)
	certMode.Store(0)
	get("api-tls-recovery", "api.test", 200, 1)
	addr := secure.addr
	stopBackend(secure)
	secure = nil
	secure = startBackend(addr, false)
	get("api-cleartext", "api.test", 502, 0)
	stopBackend(secure)
	secure = nil
	secure = startBackend(addr, true)
	get("api-cleartext-recovery", "api.test", 200, 1)
	raw, err := configuredServer(config)
	if err != nil {
		t.Fatal(err)
	}
	var invalid map[string]any
	if err = json.Unmarshal(raw, &invalid); err != nil {
		t.Fatal(err)
	}
	invalid["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)["owned"].(map[string]any)["routes"] = []any{map[string]any{"handle": []any{map[string]any{"handler": "aegvium_missing_handler"}}}}
	bad, _ := json.Marshal(invalid)
	if caddy.Load(bad, true) == nil {
		t.Fatal("invalid replacement accepted")
	}
	serverEmit(map[string]any{"kind": "config", "phase": "invalid-rejected", "sha256": hash(bad), "strict": false})
	get("api-after-invalid", "api.test", 200, 1)
	config.apiHost = "alt.test"
	if err = loadConfiguredServer(config); err != nil {
		t.Fatal(err)
	}
	configReceipt("replaced")
	get("alt-get", "alt.test", 200, 1)
	get("removed-api", "api.test", 421, 0)
	config.apiHost = "api.test"
	if err = loadConfiguredServer(config); err != nil {
		t.Fatal(err)
	}
	configReceipt("rollback")
	get("api-restored", "api.test", 200, 1)
	get("removed-alt", "alt.test", 421, 0)
	config.strict = true
	if err = loadConfiguredServer(config); err != nil {
		t.Fatal(err)
	}
	configReceipt("strict-enabled")
	get("strict-matched-app", "app.test", 200, 1)
	request("strict-matched-api", "GET", "/ok", "api.test", "api.test", "", nil, 200, 1, true)
	get("strict-cross-host", "api.test", 421, 0)
	if err = caddy.Stop(); err != nil {
		t.Fatal(err)
	}
	get("server-stop", "app.test", 0, 0)
	for _, b := range []*ownedBackend{plain, secure} {
		conn, err := net.DialTimeout("tcp4", b.addr, time.Second)
		if err != nil {
			t.Fatal("backend stopped before Caddy")
		}
		conn.Close()
	}
	addresses := []string{listen, plain.addr, secure.addr}
	stopBackend(plain)
	plain = nil
	stopBackend(secure)
	secure = nil
	for _, addr := range addresses {
		conn, err := net.DialTimeout("tcp4", addr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			t.Fatal("owned listener remains")
		}
	}
	if _, err = os.Stat(caddy.ConfigAutosavePath); !os.IsNotExist(err) {
		t.Fatal("unexpected config autosave")
	}
	serverEmit(map[string]any{"kind": "server-cleanup", "caddy_stopped": true, "backends_joined": true, "listeners_absent": true, "autosave_absent": true})
}
