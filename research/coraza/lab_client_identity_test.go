// SPDX-License-Identifier: BSD-3-Clause
package spike

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
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
	"testing"
	"time"
)

const identityDirectives = labDirectives + `SecRule REMOTE_ADDR "@ipMatch 192.0.2.9" "id:1003001,phase:1,deny,status:451,log"
SecRule REMOTE_ADDR "@ipMatch 192.0.2.10" "id:1003002,phase:1,deny,status:452,log,chain"
SecRule REMOTE_PORT "@eq 45001" "t:none"
`

type clientIdentityRow struct {
	Case         string `json:"case"`
	Enabled      bool   `json:"enabled"`
	Source       string `json:"source"`
	InputSHA     string `json:"input_sha256"`
	RulesSHA     string `json:"rules_sha256"`
	Status       int    `json:"status"`
	Backend      int    `json:"backend"`
	BodySHA      string `json:"body_sha256"`
	HeadersClean bool   `json:"headers_clean"`
	VerifiedTLS  bool   `json:"verified_tls"`
}

func TestLabClientIdentityContext(t *testing.T) {
	expected := netip.MustParseAddrPort("127.0.0.1:18120")
	valid := proxyIdentity{source: netip.MustParseAddrPort("192.0.2.9:45000"), destination: expected}
	for _, name := range []string{"missing", "wrong-type", "wrong-destination", "zero-port", "ipv6", "valid"} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			identity := valid
			switch name {
			case "wrong-type":
				ctx = context.WithValue(ctx, labClientIdentityKey{}, "192.0.2.9")
			case "wrong-destination":
				identity.destination = netip.MustParseAddrPort("127.0.0.1:1")
			case "zero-port":
				identity.source = netip.MustParseAddrPort("192.0.2.9:0")
			case "ipv6":
				identity.source = netip.MustParseAddrPort("[::1]:45000")
			}
			if name != "missing" && name != "wrong-type" {
				ctx = context.WithValue(ctx, labClientIdentityKey{}, identity)
			}
			req := httptest.NewRequest("GET", "http://app.test/", nil).WithContext(ctx)
			req.RemoteAddr = "127.0.0.1:50000"
			req.Header.Set("X-Forwarded-For", "192.0.2.9")
			called := false
			w := httptest.NewRecorder()
			labClientIdentity(expected, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				called = true
				if r.RemoteAddr != valid.source.String() {
					t.Fatal("source not propagated")
				}
			})).ServeHTTP(w, req)
			if called != (name == "valid") || (!called && (w.Code != 503 || w.Body.String() != "client identity unavailable\n")) || req.RemoteAddr != "127.0.0.1:50000" {
				t.Fatal("context admission/mutation", name, w.Code)
			}
		})
	}
	// A TLS wrapper around a non-PROXY connection must not supply context.
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	ctx := labClientContext(expected)(context.Background(), tls.Server(a, &tls.Config{}))
	if identity, ok := ctx.Value(labClientIdentityKey{}).(proxyIdentity); !ok || validLabClientIdentity(identity, expected) {
		t.Fatal("unvalidated connection accepted")
	}

	peer := &proxyV1Conn{Conn: &clientIdentityPeer{Conn: a, remote: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 50000}}, identity: valid}
	before := peer.RemoteAddr().String()
	captured := labClientContext(expected)(context.Background(), tls.Server(peer, &tls.Config{}))
	if got, ok := captured.Value(labClientIdentityKey{}).(proxyIdentity); !ok || got != valid || peer.RemoteAddr().String() != before {
		t.Fatal("connection metadata/transport changed")
	}
	stale := labClientContext(expected)(captured, tls.Server(a, &tls.Config{}))
	if got, ok := stale.Value(labClientIdentityKey{}).(proxyIdentity); !ok || validLabClientIdentity(got, expected) {
		t.Fatal("identity inherited across connections")
	}

	for _, connection := range []net.Conn{
		(*tls.Conn)(nil),
		tls.Server((*proxyV1Conn)(nil), &tls.Config{}),
		tls.Server(&proxyV1Conn{identity: valid}, &tls.Config{}),
		tls.Server(&proxyV1Conn{Conn: &clientIdentityPeer{Conn: a}, identity: valid}, &tls.Config{}),
		tls.Server(&proxyV1Conn{Conn: &clientIdentityPeer{Conn: a, remote: &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 50000}}, identity: valid}, &tls.Config{}),
	} {
		ctx := labClientContext(expected)(captured, connection)
		if got, ok := ctx.Value(labClientIdentityKey{}).(proxyIdentity); !ok || validLabClientIdentity(got, expected) {
			t.Fatal("invalid physical peer accepted")
		}
	}
	if _, e := StartLabProxy(LabProfile{DataAddress: "127.0.0.1:0", HealthAddress: "127.0.0.1:0", Ingress: expected, ProxyClientIP: true}); e == nil {
		t.Fatal("identity without TLS accepted")
	}
	if CheckLabFrontend(LabProfile{ProxyClientIP: true}) == nil {
		t.Fatal("check-only identity without TLS accepted")
	}
}

func TestLabClientIdentityWire(t *testing.T) {
	certPath, keyPath, cert, roots := tlsPathMaterial(t)
	var mu sync.Mutex
	var bodies []string
	clean := true
	backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, e := io.ReadAll(io.LimitReader(r.Body, LabBodyLimit+1))
		if e != nil {
			http.Error(w, "read", 500)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		bodies = append(bodies, string(body))
		for k := range r.Header {
			name := strings.ToLower(k)
			if name == "forwarded" || strings.HasPrefix(name, "x-forwarded-") || name == "x-real-ip" || strings.HasPrefix(name, "proxy-") {
				clean = false
			}
		}
		io.WriteString(w, "owned identity backend\n")
	}))
	backend.Config.ErrorLog = log.New(io.Discard, "", 0)
	if runtime.GOOS == "openbsd" {
		backend.Listener.Close()
		listener, e := net.Listen("tcp4", "127.0.0.1:18086")
		if e != nil {
			t.Fatal(e)
		}
		backend.Listener = listener
	}
	backend.Start()
	defer backend.Close()
	routes := []LabRoute{{Host: "app.test", Backend: backend.URL}, {Host: "api.test", Backend: backend.URL}}
	if runtime.GOOS == "openbsd" {
		if os.Geteuid() != 32767 || os.Getenv("AEGVIUM_CLIENT_IDENTITY") != "owned-guest" {
			t.Fatal("owned identity guest required")
		}
		path := filepath.Join(filepath.Dir(certPath), "identity-routes.json")
		data, e := json.Marshal(LabConfig{Version: 1, Routes: routes})
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(path, data, 0600); e != nil {
			t.Fatal(e)
		}
		for _, secure := range []bool{false, true} {
			args := []string{"-config", path, "-proxy-client-ip", "-check"}
			if secure {
				args = append(args, "-tls-cert", certPath, "-tls-key", keyPath)
			}
			command := exec.Command("/var/aegvium-lab-proxy", args...)
			command.Env = []string{"PATH=/usr/bin:/bin", "AEGVIUM_LAB_PROXY=owned-guest"}
			out, e := command.CombinedOutput()
			if secure {
				if e != nil || string(out) != "owned lab config accepted\n" {
					t.Fatal("identity check rejected")
				}
			} else {
				exit, ok := e.(*exec.ExitError)
				if !ok || exit.ExitCode() != 2 || string(out) != "lab arguments invalid\n" {
					t.Fatal("identity without TLS not rejected")
				}
			}
			for _, port := range []string{"18084", "18085"} {
				c, e := net.DialTimeout("tcp4", "127.0.0.1:"+port, 100*time.Millisecond)
				if e == nil {
					c.Close()
					t.Fatal("check-only bound listener")
				}
			}
			t.Logf("CLIENT-STARTUP tls=%t no_bind=true", secure)
		}
		if e := os.Remove(path); e != nil {
			t.Fatal(e)
		}
	}
	rulesHash := sha256.Sum256([]byte(identityDirectives))
	for _, enabled := range []bool{false, true} {
		profile := LabProfile{DataAddress: "127.0.0.1:0", HealthAddress: "127.0.0.1:0", Ingress: netip.MustParseAddrPort("127.0.0.1:18120"), Routes: routes, FrontendCertificate: cert, ProxyClientIP: enabled}
		f, e := startLabProxy(profile, identityDirectives)
		if e != nil {
			t.Fatal(e)
		}
		func() {
			defer func() {
				if e := f.Close(); e != nil {
					t.Error(e)
				}
			}()
			run := func(name, source, host, method, body string, want, delta int) {
				t.Run(name, func(t *testing.T) {
					mu.Lock()
					before := len(bodies)
					mu.Unlock()
					sourcePort := netip.MustParseAddrPort(source)
					prefix := fmt.Sprintf("PROXY TCP4 %s 127.0.0.1 %d 18120\r\n", sourcePort.Addr(), sourcePort.Port())
					wire := method + " / HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\nForwarded: for=192.0.2.9\r\nX-Forwarded-For: 192.0.2.9\r\nX-Real-IP: 192.0.2.9\r\nProxy-Authorization: synthetic\r\n"
					if method == "POST" {
						wire += "Content-Type: application/json\r\nContent-Length: " + fmt.Sprint(len(body)) + "\r\n"
					}
					wire += "\r\n" + body
					c, e := net.DialTimeout("tcp4", f.DataAddr, time.Second)
					if e != nil {
						t.Fatal(e)
					}
					defer c.Close()
					c.SetDeadline(time.Now().Add(3 * time.Second))
					if _, e = io.WriteString(c, prefix); e != nil {
						t.Fatal(e)
					}
					sni := host
					if name == "on-cross-host" {
						sni = "app.test"
					}
					tc := tls.Client(c, &tls.Config{RootCAs: roots, ServerName: sni, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}})
					if e = tc.Handshake(); e != nil {
						t.Fatal(e)
					}
					if _, e = io.WriteString(tc, wire); e != nil {
						t.Fatal(e)
					}
					response, e := http.ReadResponse(bufio.NewReader(tc), &http.Request{Method: method})
					if e != nil {
						t.Fatal(e)
					}
					_, e = io.ReadAll(io.LimitReader(response.Body, 8193))
					response.Body.Close()
					if e != nil {
						t.Fatal(e)
					}
					state := tc.ConnectionState()
					hash := sha256.Sum256([]byte(fmt.Sprint(enabled) + "\x00" + prefix + "\x00" + sni + "\x00" + wire))
					row := clientIdentityRow{Case: name, Enabled: enabled, Source: source, InputSHA: hex.EncodeToString(hash[:]), RulesSHA: hex.EncodeToString(rulesHash[:]), Status: response.StatusCode, HeadersClean: true, VerifiedTLS: state.HandshakeComplete && len(state.VerifiedChains) > 0 && state.NegotiatedProtocol == "http/1.1"}
					mu.Lock()
					row.Backend = len(bodies) - before
					if row.Backend == 1 {
						h := sha256.Sum256([]byte(bodies[before]))
						row.BodySHA = hex.EncodeToString(h[:])
					}
					row.HeadersClean = clean
					mu.Unlock()
					raw, _ := json.Marshal(row)
					t.Log("CLIENT-IDENTITY " + string(raw))
					if row.Status != want || row.Backend != delta || !row.HeadersClean || !row.VerifiedTLS {
						t.Fatalf("identity outcome %+v wanted %d/%d", row, want, delta)
					}
					if delta == 1 {
						h := sha256.Sum256([]byte(body))
						if row.BodySHA != hex.EncodeToString(h[:]) {
							t.Fatal("identity body drift")
						}
					}
				})
			}
			if !enabled {
				run("off-asserted-ip", "192.0.2.9:45000", "app.test", "GET", "", 200, 1)
				return
			}
			run("on-asserted-ip", "192.0.2.9:45000", "app.test", "GET", "", 451, 0)
			run("on-asserted-port", "192.0.2.10:45001", "app.test", "GET", "", 452, 0)
			run("on-spoof-headers", "192.0.2.10:45002", "app.test", "GET", "", 200, 1)
			run("on-json", "192.0.2.10:45002", "api.test", "POST", `{"payload":"ordinary"}`, 200, 1)
			run("on-script", "192.0.2.10:45002", "app.test", "POST", `{"payload":"<script>alert(1)</script>"}`, 403, 0)
			run("on-cross-host", "192.0.2.10:45002", "api.test", "GET", "", 421, 0)
			if e := f.reload([]LabRoute{{Host: "alt.test", Backend: backend.URL}}, identityDirectives); e != nil {
				t.Fatal(e)
			}
			run("on-reload-alt", "192.0.2.9:45000", "alt.test", "GET", "", 451, 0)
			if e := f.reload(routes, identityDirectives); e != nil {
				t.Fatal(e)
			}
			run("on-rollback", "192.0.2.9:45000", "app.test", "GET", "", 451, 0)
			run("on-recovery", "192.0.2.10:45002", "app.test", "GET", "", 200, 1)
		}()
		for _, address := range []string{f.DataAddr, f.HealthAddr} {
			c, e := net.DialTimeout("tcp4", address, 100*time.Millisecond)
			if e == nil {
				c.Close()
				t.Fatal("identity listener remains")
			}
		}
		if t.Failed() {
			return
		}
	}
	// Close/join is independent of the backend, which remains alive here.
	c, e := net.DialTimeout("tcp4", strings.TrimPrefix(backend.URL, "http://"), time.Second)
	if e != nil {
		t.Fatal(e)
	}
	c.Close()
	backend.Close()
	for _, path := range []string{certPath, keyPath} {
		if e := os.Remove(path); e != nil {
			t.Fatal(e)
		}
		if _, e := os.Stat(path); !os.IsNotExist(e) {
			t.Fatal("identity asset remains")
		}
	}
	t.Log("CLIENT-FINAL companion_stopped=true backend_alive_at_stop=true assets_removed=true")
}

type clientIdentityPeer struct {
	net.Conn
	remote net.Addr
}

func (c *clientIdentityPeer) RemoteAddr() net.Addr { return c.remote }
