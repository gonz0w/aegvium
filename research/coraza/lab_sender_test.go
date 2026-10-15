// SPDX-License-Identifier: BSD-3-Clause
package spike

import (
	"bufio"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
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

type senderRow struct {
	Phase        string `json:"phase"`
	Case         string `json:"case"`
	InputSHA     string `json:"input_sha256"`
	Status       int    `json:"status"`
	Backend      int    `json:"backend"`
	Authority    string `json:"authority"`
	BodySHA      string `json:"body_sha256"`
	HeadersClean bool   `json:"headers_clean"`
	Connected    bool   `json:"connected"`
	VerifiedTLS  bool   `json:"verified_tls"`
	Error        string `json:"error"`
}

func TestLabSenderOpen(t *testing.T) { runSenderPath(t, "baseline", false) }
func TestLabSenderContainment(t *testing.T) {
	if runtime.GOOS != "openbsd" || os.Getenv("AEGVIUM_LAB_SENDER") != "owned-guest" {
		t.Skip("owned OpenBSD PF/relayd path required")
	}
	if os.Geteuid() != 32767 {
		t.Fatal("fixture UID")
	}
	phase := os.Getenv("AEGVIUM_SENDER_PHASE")
	if phase != "baseline" && phase != "protected" && phase != "rollback" && phase != "reprotected" {
		t.Fatal("sender phase")
	}
	runSenderPath(t, phase, true)
}

func runSenderPath(t *testing.T, phase string, guest bool) {
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
			name := strings.ToLower(k)
			if name == "forwarded" || strings.HasPrefix(name, "x-forwarded-") || name == "x-real-ip" || name == "x-original-url" || strings.HasPrefix(name, "proxy-") {
				clean = false
			}
		}
		mu.Lock()
		effects = append(effects, effect{r.Host, string(body), clean})
		mu.Unlock()
		io.WriteString(w, "owned sender backend\n")
	})
	makeBackend := func(port string, secure bool) *httptest.Server {
		s := httptest.NewUnstartedServer(receive)
		s.Config.ErrorLog = log.New(io.Discard, "", 0)
		if guest {
			s.Listener.Close()
			l, e := net.Listen("tcp4", "127.0.0.1:"+port)
			if e != nil {
				t.Fatal(e)
			}
			s.Listener = l
		}
		if secure {
			s.TLS = &tls.Config{Certificates: []tls.Certificate{*cert}, MinVersion: tls.VersionTLS12}
			s.StartTLS()
		} else {
			s.Start()
		}
		return s
	}
	plain := makeBackend("18086", false)
	defer plain.Close()
	api := makeBackend("18087", true)
	defer api.Close()
	config := LabConfig{Version: 1, Routes: []LabRoute{{Host: "app.test", Backend: plain.URL}, {Host: "api.test", Backend: api.URL, TLSServerName: "api.test", TLSCAFile: certPath}}}
	configPath := filepath.Join(filepath.Dir(certPath), "sender-routes.json")
	raw, e := json.Marshal(config)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(configPath, raw, 0600); e != nil {
		t.Fatal(e)
	}
	profile := config.Profile()
	profile.FrontendCertificate = cert
	var proxy *LabProxy
	var command *exec.Cmd
	var done chan error
	stopped := false
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
				t.Error("sender CLI stop timeout")
			}
		} else if e := proxy.Close(); e != nil {
			t.Error(e)
		}
	}
	if guest {
		ack := &labAckWriter{events: make(chan string, 4)}
		command = exec.Command("/var/aegvium-lab-proxy", "-config", configPath, "-tls-cert", certPath, "-tls-key", keyPath)
		command.Env = []string{"PATH=/usr/bin:/bin", "AEGVIUM_LAB_PROXY=owned-guest"}
		command.Stdout = ack
		command.Stderr = ack
		if e = command.Start(); e != nil {
			t.Fatal(e)
		}
		done = make(chan error, 1)
		go func() { done <- command.Wait() }()
		defer stop()
		select {
		case line := <-ack.events:
			if line != "owned lab companion ready" {
				t.Fatal("sender CLI ack")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("sender startup deadline")
		}
	} else {
		profile.DataAddress = "127.0.0.1:0"
		profile.HealthAddress = "127.0.0.1:0"
		proxy, e = StartLabProxy(profile)
		if e != nil {
			t.Fatal(e)
		}
		defer stop()
		profile.DataAddress = proxy.DataAddr
		profile.HealthAddress = proxy.HealthAddr
	}
	public, e := os.ReadFile(certPath)
	if e != nil {
		t.Fatal(e)
	}
	publicHash := sha256.Sum256(public)
	configHash := sha256.Sum256(raw)
	t.Logf("SENDER-ASSETS phase=%s cert_sha256=%x config_sha256=%x", phase, publicHash, configHash)
	tlsConfig := func(sni string) *tls.Config {
		return &tls.Config{RootCAs: roots, ServerName: sni, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}
	}
	dial := func(direct bool) (net.Conn, error) {
		address := profile.DataAddress
		if guest && !direct {
			address = "127.0.0.1:18120"
		}
		return net.DialTimeout("tcp4", address, time.Second)
	}
	prefix := "PROXY TCP4 192.0.2.9 127.0.0.1 45000 18120\r\n"
	readyUntil := time.Now().Add(7 * time.Second)
	for {
		c, e := dial(false)
		if e == nil {
			c.SetDeadline(time.Now().Add(2 * time.Second))
			if !guest {
				_, e = io.WriteString(c, prefix)
			}
			if e == nil {
				tc := tls.Client(c, tlsConfig("app.test"))
				e = tc.Handshake()
				tc.Close()
			} else {
				c.Close()
			}
		}
		if e == nil {
			break
		}
		if time.Now().After(readyUntil) {
			t.Fatal("sender ingress readiness", e)
		}
		time.Sleep(100 * time.Millisecond)
	}
	protected := phase == "protected" || phase == "reprotected"
	run := func(name, sni, host, method, body, mode string, want, delta int) {
		t.Run(name, func(t *testing.T) {
			hash := sha256.Sum256([]byte(strings.Join([]string{sni, host, method, body, mode}, "\x00")))
			row := senderRow{Phase: phase, Case: name, InputSHA: hex.EncodeToString(hash[:]), HeadersClean: true}
			mu.Lock()
			before := len(effects)
			mu.Unlock()
			request := method + " / HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\nForwarded: for=192.0.2.80\r\nX-Forwarded-For: 192.0.2.81\r\nProxy-Authorization: synthetic\r\n"
			if method == "POST" {
				request += "Content-Type: application/json\r\nContent-Length: " + fmt.Sprint(len(body)) + "\r\n"
			}
			request += "\r\n" + body
			direct := strings.HasPrefix(mode, "direct-")
			var c net.Conn
			var e error
			if mode == "health" {
				c, e = net.DialTimeout("tcp4", profile.HealthAddress, time.Second)
				request = "GET /ready HTTP/1.1\r\nHost: health.test\r\nConnection: close\r\n\r\n"
			} else {
				c, e = dial(direct)
			}
			row.Connected = e == nil
			if e != nil {
				var timeout net.Error
				if !direct || !protected || (errors.As(e, &timeout) && timeout.Timeout()) || (!errors.Is(e, syscall.ECONNREFUSED) && !errors.Is(e, syscall.EHOSTUNREACH) && !errors.Is(e, syscall.EACCES) && !errors.Is(e, syscall.EPERM)) {
					t.Fatal("unexpected sender connect failure", e)
				}
				row.Error = "denied"
			} else {
				c.SetDeadline(time.Now().Add(3 * time.Second))
				var wire net.Conn = c
				if mode != "health" && mode != "direct-plain" {
					if (direct && mode != "direct-bare-tls") || (!guest && !direct) {
						_, e = io.WriteString(c, prefix)
					}
					if e == nil {
						tc := tls.Client(c, tlsConfig(sni))
						wire = tc
						e = tc.Handshake()
						if e == nil {
							state := tc.ConnectionState()
							row.VerifiedTLS = state.HandshakeComplete && len(state.VerifiedChains) > 0 && state.NegotiatedProtocol == "http/1.1"
						}
					}
					if e != nil {
						row.Error = "tls"
					}
				}
				if e == nil {
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
					if e != nil {
						row.Error = "prefix"
					}
				}
				wire.Close()
			}
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
			if direct && protected {
				want, delta = 0, 0
			}
			raw, _ := json.Marshal(row)
			t.Log("SENDER-PATH " + string(raw))
			if row.Status != want || row.Backend != delta || !row.HeadersClean {
				t.Fatalf("sender outcome %+v wanted %d/%d", row, want, delta)
			}
			if direct && protected {
				if row.Connected || row.Error != "denied" || row.VerifiedTLS {
					t.Fatal("protected direct socket bypassed")
				}
			} else {
				if !row.Connected {
					t.Fatal("control socket not connected")
				}
				if want != 0 && mode != "health" && !row.VerifiedTLS {
					t.Fatal("verified TLS absent")
				}
				if (want != 0) != (row.Error == "") {
					t.Fatal("hidden client outcome")
				}
			}
			if delta == 1 {
				expected := sha256.Sum256([]byte(body))
				if row.Authority != host || row.BodySHA != hex.EncodeToString(expected[:]) {
					t.Fatal("sender backend bytes/authority")
				}
			}
		})
	}
	run("ingress-app", "app.test", "app.test", "GET", "", "ingress", 200, 1)
	run("ingress-api", "api.test", "api.test", "GET", "", "ingress", 200, 1)
	run("ingress-json", "api.test", "api.test", "POST", `{"payload":"ordinary"}`, "ingress", 200, 1)
	run("ingress-script", "app.test", "app.test", "POST", `{"payload":"<script>alert(1)</script>"}`, "ingress", 403, 0)
	run("cross-host", "app.test", "api.test", "GET", "", "ingress", 421, 0)
	run("health", "", "health.test", "GET", "", "health", 200, 0)
	run("direct-app", "app.test", "app.test", "GET", "", "direct-prefix", 200, 1)
	run("direct-api", "api.test", "api.test", "GET", "", "direct-prefix", 200, 1)
	run("direct-bare-tls", "app.test", "app.test", "GET", "", "direct-bare-tls", 0, 0)
	run("direct-plain", "", "app.test", "GET", "", "direct-plain", 0, 0)
	run("ingress-after-direct", "api.test", "api.test", "GET", "", "ingress", 200, 1)
	stop()
	absent := func(address string) bool {
		c, e := net.DialTimeout("tcp4", address, 100*time.Millisecond)
		if e == nil {
			c.Close()
			return false
		}
		return true
	}
	// For a protected listener this check alone is insufficient; the CLI exit/join above is independent.
	if !absent(profile.DataAddress) || !absent(profile.HealthAddress) {
		t.Fatal("sender listener remains")
	}
	for _, s := range []*httptest.Server{plain, api} {
		c, e := net.DialTimeout("tcp4", s.Listener.Addr().String(), time.Second)
		if e != nil {
			t.Fatal("sender backend absent before cleanup", e)
		}
		c.Close()
	}
	plain.Close()
	api.Close()
	if !absent(plain.Listener.Addr().String()) || !absent(api.Listener.Addr().String()) {
		t.Fatal("sender backend listener remains")
	}
	for _, path := range []string{configPath, keyPath, certPath} {
		if e = os.Remove(path); e != nil {
			t.Fatal(e)
		}
		if _, e = os.Lstat(path); !errors.Is(e, os.ErrNotExist) {
			t.Fatal("sender asset remains")
		}
	}
	t.Logf("SENDER-FINAL phase=%s companion_stopped=true backends_alive_at_stop=true listeners_absent=true assets_removed=true", phase)
}
