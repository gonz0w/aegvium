// SPDX-License-Identifier: BSD-3-Clause
package spike

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

type tlsPathRow struct {
	Case         string `json:"case"`
	InputSHA     string `json:"input_sha256"`
	Status       int    `json:"status"`
	Backend      int    `json:"backend"`
	Authority    string `json:"authority"`
	BodySHA      string `json:"body_sha256"`
	HeadersClean bool   `json:"headers_clean"`
	ClientError  bool   `json:"client_error"`
	TLS          bool   `json:"verified_tls"`
}

func tlsPathMaterial(t *testing.T) (string, string, *tls.Certificate, *x509.CertPool) {
	t.Helper()
	private, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"app.test", "api.test", "alt.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, leaf, leaf, &private.PublicKey, private)
	if e != nil {
		t.Fatal(e)
	}
	rawkey, e := x509.MarshalPKCS8PrivateKey(private)
	if e != nil {
		t.Fatal(e)
	}
	certPath := filepath.Join(t.TempDir(), "frontend.pem")
	keyPath := filepath.Join(filepath.Dir(certPath), "frontend.key")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if e = os.WriteFile(certPath, certPEM, 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: rawkey}), 0600); e != nil {
		t.Fatal(e)
	}
	cert, e := ReadLabCertificate(certPath, keyPath)
	if e != nil {
		t.Fatal(e)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certPEM) {
		t.Fatal("fixture roots")
	}
	return certPath, keyPath, cert, roots
}

func TestLabFrontendTLS(t *testing.T) { runTLSPath(t, false) }
func TestLabTLSPassthrough(t *testing.T) {
	if runtime.GOOS != "openbsd" || os.Getenv("AEGVIUM_LAB_TLS") != "owned-guest" {
		t.Skip("owned OpenBSD TCP relayd path required")
	}
	if os.Geteuid() != 32767 {
		t.Fatal("fixture UID")
	}
	runTLSPath(t, true)
}

func runTLSPath(t *testing.T, guest bool) {
	certPath, keyPath, cert, roots := tlsPathMaterial(t)
	var mu sync.Mutex
	type effect struct {
		host, body string
		clean      bool
	}
	var effects []effect
	receive := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, e := io.ReadAll(io.LimitReader(r.Body, LabBodyLimit+1))
		if e != nil {
			http.Error(w, "read", 500)
			return
		}
		clean := true
		for k := range r.Header {
			l := strings.ToLower(k)
			if l == "forwarded" || strings.HasPrefix(l, "x-forwarded-") || l == "x-real-ip" || l == "x-original-url" || l == "x-rewrite-url" || strings.HasPrefix(l, "proxy-") {
				clean = false
			}
		}
		mu.Lock()
		effects = append(effects, effect{r.Host, string(body), clean})
		mu.Unlock()
		io.WriteString(w, "owned backend\n")
	})
	plain := httptest.NewServer(receive)
	defer plain.Close()
	api := httptest.NewUnstartedServer(receive)
	api.TLS = &tls.Config{Certificates: []tls.Certificate{*cert}, MinVersion: tls.VersionTLS12}
	api.Config.ErrorLog = log.New(io.Discard, "", 0)
	api.StartTLS()
	defer api.Close()
	config := LabConfig{Version: 1, Routes: []LabRoute{{Host: "app.test", Backend: plain.URL}, {Host: "api.test", Backend: api.URL, TLSServerName: "api.test", TLSCAFile: certPath}}}
	profile := config.Profile()
	profile.FrontendCertificate = cert
	if !guest {
		profile.DataAddress = "127.0.0.1:0"
		profile.HealthAddress = "127.0.0.1:0"
	}
	configPath := filepath.Join(filepath.Dir(certPath), "routes.json")
	writeConfig := func(c LabConfig) {
		raw, e := json.Marshal(c)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(configPath, raw, 0600); e != nil {
			t.Fatal(e)
		}
	}
	writeConfig(config)
	publicBytes, e := os.ReadFile(certPath)
	if e != nil {
		t.Fatal(e)
	}
	configBytes, e := os.ReadFile(configPath)
	if e != nil {
		t.Fatal(e)
	}
	publicSHA := sha256.Sum256(publicBytes)
	configSHA := sha256.Sum256(configBytes)
	t.Logf("TLS-ASSETS cert_sha256=%x config_sha256=%x", publicSHA, configSHA)
	args := []string{"-config", configPath, "-tls-cert", certPath, "-tls-key", keyPath}
	var f *LabProxy
	var command *exec.Cmd
	var done chan error
	var ack *labAckWriter
	stopped := false
	waitAck := func(want string) {
		select {
		case got := <-ack.events:
			if got != want {
				t.Fatalf("ack %q != %q", got, want)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("missing CLI ack")
		}
	}
	absent := func(address string) bool {
		c, e := net.DialTimeout("tcp4", address, 100*time.Millisecond)
		if e == nil {
			c.Close()
			return false
		}
		return true
	}
	if guest {
		check := func(a []string) error {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			c := exec.CommandContext(ctx, "/var/aegvium-lab-proxy", a...)
			c.Env = []string{"PATH=/usr/bin:/bin", "AEGVIUM_LAB_PROXY=owned-guest"}
			return c.Run()
		}
		if e := check(append(append([]string{}, args...), "-check")); e != nil {
			t.Fatal("TLS check failed", e)
		}
		invalid := [][]string{
			{"-config", configPath, "-tls-cert", certPath, "-check"},
			{"-config", configPath, "-tls-cert", keyPath, "-tls-key", certPath, "-check"},
			{"-config", configPath, "-tls-cert", certPath, "-tls-key", keyPath + ".missing"},
		}
		reject := func(a []string) {
			e := check(a)
			var exit *exec.ExitError
			if !errors.As(e, &exit) || exit.ExitCode() != 2 {
				t.Fatal("TLS rejection exit mismatch", e)
			}
		}
		for _, a := range invalid {
			reject(a)
		}
		bad := config
		bad.Routes = append(append([]LabRoute{}, config.Routes...), LabRoute{Host: "uncovered.test", Backend: plain.URL})
		writeConfig(bad)
		reject(args)
		writeConfig(config)
		if !absent(profile.DataAddress) || !absent(profile.HealthAddress) {
			t.Fatal("check/rejection bound listener")
		}
		t.Log("TLS-STARTUP checked=1 rejected=4 listeners_absent=true")
		ack = &labAckWriter{events: make(chan string, 16)}
		command = exec.Command("/var/aegvium-lab-proxy", args...)
		command.Env = []string{"PATH=/usr/bin:/bin", "AEGVIUM_LAB_PROXY=owned-guest"}
		command.Stdout = ack
		command.Stderr = ack
		if e := command.Start(); e != nil {
			t.Fatal(e)
		}
		done = make(chan error, 1)
		go func() { done <- command.Wait() }()
		waitAck("owned lab companion ready")
	} else {
		var e error
		f, e = StartLabProxy(profile)
		if e != nil {
			t.Fatal(e)
		}
		profile.DataAddress = f.DataAddr
		profile.HealthAddress = f.HealthAddr
	}
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		if guest {
			if e := command.Process.Signal(syscall.SIGTERM); e != nil {
				t.Error(e)
			}
			select {
			case e := <-done:
				if e != nil {
					t.Error(e)
				}
			case <-time.After(6 * time.Second):
				command.Process.Kill()
				t.Error("CLI stop timeout")
			}
		} else if e := f.Close(); e != nil {
			t.Error(e)
		}
	}
	defer stop()
	dial := func(direct bool) (net.Conn, error) {
		address := profile.DataAddress
		if guest && !direct {
			address = "127.0.0.1:18120"
		}
		c, e := net.DialTimeout("tcp4", address, time.Second)
		if e != nil {
			return nil, e
		}
		c.SetDeadline(time.Now().Add(3 * time.Second))
		if !guest || direct {
			_, e = io.WriteString(c, "PROXY TCP4 192.0.2.9 127.0.0.1 45000 18120\r\n")
			if e != nil {
				c.Close()
				return nil, e
			}
		}
		return c, nil
	}
	clientConfig := func(sni string) *tls.Config {
		return &tls.Config{RootCAs: roots, ServerName: sni, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}
	}
	// Verify actual ingress readiness with TLS only, never a backend-effecting probe.
	deadline := time.Now().Add(7 * time.Second)
	for {
		c, e := dial(false)
		if e == nil {
			tc := tls.Client(c, clientConfig("app.test"))
			e = tc.Handshake()
			tc.Close()
		}
		if e == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("TLS ingress not ready", e)
		}
		time.Sleep(100 * time.Millisecond)
	}
	count := func() int { mu.Lock(); defer mu.Unlock(); return len(effects) }
	run := func(name, sni, host, method, body string, want, delta int, mode string) {
		t.Run(name, func(t *testing.T) {
			before := count()
			inputHash := sha256.Sum256([]byte(strings.Join([]string{sni, host, method, body, mode}, "\x00")))
			row := tlsPathRow{Case: name, HeadersClean: true, InputSHA: hex.EncodeToString(inputHash[:])}
			request := method + " / HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\nForwarded: for=192.0.2.80\r\nX-Forwarded-For: 192.0.2.81\r\nProxy-Authorization: synthetic\r\n"
			if method == "POST" {
				request += "Content-Type: application/json\r\nContent-Length: " + fmt.Sprint(len(body)) + "\r\n"
			}
			request += "\r\n" + body
			c, e := dial(mode == "forged-prefix")
			if mode == "bare-tls" {
				if c != nil {
					c.Close()
				}
				c, e = net.DialTimeout("tcp4", profile.DataAddress, time.Second)
				if c != nil {
					c.SetDeadline(time.Now().Add(3 * time.Second))
				}
			}
			if e == nil {
				var wire net.Conn = c
				cfg := clientConfig(sni)
				if mode == "missing-sni" {
					cfg.ServerName = "127.0.0.1"
				} // Go omits IP SNI, still verifies explicitly.
				if mode == "untrusted" {
					cfg.RootCAs = x509.NewCertPool()
				}
				if mode == "h2" {
					cfg.NextProtos = []string{"h2"}
				}
				if mode == "tls10" {
					cfg.MinVersion = tls.VersionTLS10
					cfg.MaxVersion = tls.VersionTLS10
				}
				if mode != "plain" && mode != "slow" {
					tc := tls.Client(c, cfg)
					wire = tc
					e = tc.Handshake()
					if e == nil {
						state := tc.ConnectionState()
						row.TLS = state.HandshakeComplete && len(state.VerifiedChains) > 0 && state.NegotiatedProtocol == "http/1.1"
					}
				}
				if mode == "slow" {
					started := time.Now()
					_, e = wire.Write([]byte{22, 3, 3, 0, 16, 1})
					if e == nil {
						var b [1]byte
						_, e = wire.Read(b[:])
					}
					var timeout net.Error
					if e == nil || (errors.As(e, &timeout) && timeout.Timeout()) || time.Since(started) > 2500*time.Millisecond {
						t.Fatal("TLS handshake was not closed within server budget", e)
					}
				}
				if e == nil && mode != "slow" {
					_, e = io.WriteString(wire, request)
					if e == nil {
						var response *http.Response
						response, e = http.ReadResponse(bufio.NewReader(wire), &http.Request{Method: method})
						if e == nil {
							row.Status = response.StatusCode
							_, e = io.ReadAll(io.LimitReader(response.Body, 8193))
							response.Body.Close()
						}
					}
				}
				wire.Close()
			}
			row.ClientError = e != nil
			// Every successful effect completes before a response; failures receive a bounded quiescence witness.
			if row.Status == 0 {
				time.Sleep(50 * time.Millisecond)
			}
			mu.Lock()
			row.Backend = len(effects) - before
			if row.Backend == 1 {
				v := effects[before]
				row.Authority = v.host
				h := sha256.Sum256([]byte(v.body))
				row.BodySHA = hex.EncodeToString(h[:])
				row.HeadersClean = v.clean
			}
			mu.Unlock()
			raw, _ := json.Marshal(row)
			t.Log("TLS-PATH " + string(raw))
			if row.Status != want || row.Backend != delta || !row.HeadersClean || row.ClientError != (want == 0) {
				t.Fatalf("TLS result %+v wanted %d/%d", row, want, delta)
			}
			if delta == 1 {
				h := sha256.Sum256([]byte(body))
				if row.BodySHA != hex.EncodeToString(h[:]) || row.Authority != strings.TrimSuffix(host, ":18120") {
					t.Fatal("backend bytes/authority")
				}
			}
			if want != 0 && mode != "plain" && !row.TLS {
				t.Fatal("verified TLS missing")
			}
		})
	}
	run("app-match", "app.test", "app.test", "GET", "", 200, 1, "")
	run("api-match", "api.test", "api.test", "GET", "", 200, 1, "")
	run("app-port", "app.test", "app.test:18120", "GET", "", 200, 1, "")
	run("api-port", "api.test", "api.test:18120", "GET", "", 200, 1, "")
	run("cross-app-api", "app.test", "api.test", "GET", "", 421, 0, "")
	run("cross-api-app", "api.test", "app.test", "GET", "", 421, 0, "")
	run("wrong-port", "api.test", "api.test:18087", "GET", "", 421, 0, "")
	run("trailing-dot", "app.test", "app.test.", "GET", "", 421, 0, "")
	run("folded-host", "app.test", "App.test", "GET", "", 421, 0, "")
	run("unknown-host", "app.test", "unknown.test", "GET", "", 421, 0, "")
	run("missing-sni", "", "app.test", "GET", "", 0, 0, "missing-sni")
	run("unknown-sni", "unknown.test", "app.test", "GET", "", 0, 0, "")
	run("untrusted-cert", "app.test", "app.test", "GET", "", 0, 0, "untrusted")
	run("h2-only", "app.test", "app.test", "GET", "", 0, 0, "h2")
	run("tls10-only", "app.test", "app.test", "GET", "", 0, 0, "tls10")
	run("plaintext", "app.test", "app.test", "GET", "", 400, 0, "plain")
	run("bare-tls", "app.test", "app.test", "GET", "", 0, 0, "bare-tls")
	run("slow-tls", "app.test", "app.test", "GET", "", 0, 0, "slow")
	run("after-slow", "app.test", "app.test", "GET", "", 200, 1, "")
	run("json", "api.test", "api.test", "POST", `{"payload":"ordinary"}`, 200, 1, "")
	run("script", "app.test", "app.test", "POST", `{"payload":"<script>alert(1)</script>"}`, 403, 0, "")
	run("oversize", "app.test", "app.test", "POST", strings.Repeat("x", LabBodyLimit+1), 413, 0, "")
	// Deliberate characterization: a local sender can forge a valid prefix and reach inspected service.
	run("forged-local-prefix", "app.test", "app.test", "GET", "", 200, 1, "forged-prefix")
	reload := func(c LabConfig, want bool) {
		if guest {
			writeConfig(c)
			if e := command.Process.Signal(syscall.SIGHUP); e != nil {
				t.Fatal(e)
			}
			message := "owned lab reload rejected"
			if want {
				message = "owned lab reload accepted"
			}
			waitAck(message)
		} else {
			e := f.Reload(c.Routes)
			if (e == nil) != want {
				t.Fatal("reload admission", e)
			}
		}
	}
	bad := LabConfig{Version: 1, Routes: []LabRoute{{Host: "uncovered.test", Backend: plain.URL}}}
	reload(bad, false)
	run("after-invalid", "api.test", "api.test", "GET", "", 200, 1, "")
	alternate := LabConfig{Version: 1, Routes: []LabRoute{config.Routes[0], {Host: "alt.test", Backend: api.URL, TLSServerName: "api.test", TLSCAFile: certPath}}}
	reload(alternate, true)
	run("alt-active", "alt.test", "alt.test", "GET", "", 200, 1, "")
	run("removed-api", "api.test", "api.test", "GET", "", 0, 0, "")
	reload(config, true)
	run("api-restored", "api.test", "api.test", "GET", "", 200, 1, "")
	run("removed-alt", "alt.test", "alt.test", "GET", "", 0, 0, "")
	stop()
	run("companion-stop", "app.test", "app.test", "GET", "", 0, 0, "")
	if !absent(profile.DataAddress) || !absent(profile.HealthAddress) {
		t.Fatal("companion listener leak")
	}
	// Backend alive witness is independent of failed ingress after companion stop.
	for _, address := range []string{plain.Listener.Addr().String(), api.Listener.Addr().String()} {
		c, e := net.DialTimeout("tcp4", address, time.Second)
		if e != nil {
			t.Fatal("backend unexpectedly absent", e)
		}
		c.Close()
	}
	plain.Close()
	api.Close()
	if !absent(plain.Listener.Addr().String()) || !absent(api.Listener.Addr().String()) {
		t.Fatal("backend listener leak")
	}
	if e := os.Remove(keyPath); e != nil {
		t.Fatal(e)
	}
	if e := os.Remove(certPath); e != nil {
		t.Fatal(e)
	}
	if e := os.Remove(configPath); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Lstat(keyPath); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("key remains")
	}
	t.Log("TLS-FINAL reload_accepted=2 reload_rejected=1 companion_stopped=true backends_alive_at_stop=true listeners_absent=true assets_removed=true")
}

func TestLabFrontendCertificateRejects(t *testing.T) {
	certPath, keyPath, cert, _ := tlsPathMaterial(t)
	routes := []LabRoute{{Host: "app.test", Backend: "http://127.0.0.1:18086"}}
	if _, e := labFrontendCertificate(cert, routes); e != nil {
		t.Fatal(e)
	}
	for _, bad := range []*tls.Certificate{{}, {Certificate: [][]byte{[]byte("bad")}, PrivateKey: cert.PrivateKey}, cert} {
		current := routes
		if bad == cert {
			current = []LabRoute{{Host: "uncovered.test"}}
		}
		if _, e := labFrontendCertificate(bad, current); e == nil {
			t.Fatal("invalid certificate admitted")
		}
	}
	if _, e := ReadLabCertificate(keyPath, certPath); e == nil {
		t.Fatal("swapped keypair admitted")
	}
	target := filepath.Join(filepath.Dir(certPath), "link")
	if e := os.Symlink(keyPath, target); e != nil {
		t.Fatal(e)
	}
	if _, e := ReadLabCertificate(certPath, target); e == nil {
		t.Fatal("symlink key admitted")
	}
	// Listener validation must precede binds and keep caller certificate input independent.
	p := LabProfile{DataAddress: "127.0.0.1:0", HealthAddress: "127.0.0.1:0", Ingress: netip.MustParseAddrPort("127.0.0.1:18120"), Routes: []LabRoute{{Host: "uncovered.test", Backend: "http://127.0.0.1:18086"}}, FrontendCertificate: cert}
	if f, e := StartLabProxy(p); e == nil {
		f.Close()
		t.Fatal("uncovered route bound")
	}
}
