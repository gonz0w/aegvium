// SPDX-License-Identifier: BSD-3-Clause
package comparison

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	if runtime.GOOS == "openbsd" && (os.Getenv("AEGVIUM_CONNECTOR_REPEAT") != "owned-guest" || os.Geteuid() == 0) {
		os.Exit(2)
	}
	os.Exit(m.Run())
}

const directives = "Include @coraza.conf-recommended\nSecRuleEngine On\nSecRequestBodyInMemoryLimit 128\nSecRequestBodyLimit 128\nInclude @crs-setup.conf.example\nInclude @owasp_crs/*.conf\n" +
	`SecRule RESPONSE_HEADERS:X-Lab-Response "@streq blocked" "id:100001,phase:3,deny,status:406,nolog"` + "\n" +
	`SecRule RESPONSE_BODY "@contains aegvium-leak" "id:100002,phase:4,deny,status:406,nolog"` + "\n"

func hash(data []byte) string { h := sha256.Sum256(data); return hex.EncodeToString(h[:]) }
func emit(t *testing.T, value any) {
	t.Helper()
	b, e := json.Marshal(value)
	if e != nil {
		t.Fatal(e)
	}
	t.Log("CONNECTOR " + string(b))
}

type source struct {
	io.ReadCloser
	closed atomic.Int64
}

func (s *source) Close() error { s.closed.Add(1); return s.ReadCloser.Close() }

type observation struct {
	Profile      string `json:"profile"`
	Case         string `json:"case"`
	Input        string `json:"input_sha256"`
	Status       int    `json:"status"`
	Response     string `json:"response_sha256"`
	Backend      int    `json:"backend"`
	Body         string `json:"body_sha256"`
	Host         string `json:"host"`
	Spoof        bool   `json:"spoof_preserved"`
	SourceClosed int64  `json:"source_closed"`
}

func TestConnectorWire(t *testing.T) {
	benign := `{"payload":"ordinary"}`
	script := `{"payload":"<script>alert(1)</script>"}`
	sql := url.Values{"payload": {"' OR 1=1--"}}.Encode()
	over := `{"payload":"` + strings.Repeat("x", 129-len(`{"payload":""}`)) + `"}`
	fixed := func(s string) string { return fmt.Sprintf("Content-Length: %d\r\n", len(s)) }
	chunk := func(s string) string { return fmt.Sprintf("%x\r\n%s\r\n0\r\n\r\n", len(s), s) }
	cases := []struct {
		name, method, path, headers, body string
		engine, caddy, backend            int
	}{
		{"benign-get", "GET", "/", "", "", 200, 200, 1},
		{"fixed-json", "POST", "/", fixed(benign) + "Content-Type: application/json\r\n", benign, 200, 200, 1},
		{"json-script", "POST", "/", fixed(script) + "Content-Type: application/json\r\n", script, 403, 403, 0},
		{"form-sql", "POST", "/", fixed(sql) + "Content-Type: application/x-www-form-urlencoded\r\n", sql, 403, 403, 0},
		{"query-sql", "GET", "/?payload=%27%20OR%201%3D1--", "", "", 403, 403, 0},
		{"fixed-over", "POST", "/", fixed(over) + "Content-Type: application/json\r\n", over, 413, 413, 0},
		{"chunked-json", "POST", "/", "Transfer-Encoding: chunked\r\nContent-Type: application/json\r\n", chunk(benign), 200, 200, 1},
		{"chunked-over", "POST", "/", "Transfer-Encoding: chunked\r\nContent-Type: application/json\r\n", chunk(over), 413, 413, 0},
		{"short-fixed", "POST", "/", fmt.Sprintf("Content-Length: %d\r\nContent-Type: application/json\r\n", len(benign)+1), benign, 200, 500, 0},
		{"bad-chunk", "POST", "/", "Transfer-Encoding: chunked\r\nContent-Type: application/json\r\n", "gg\r\n", 200, 500, 0},
		{"invalid-json", "POST", "/", fixed(`{"payload":`) + "Content-Type: application/json\r\n", `{"payload":`, 400, 400, 0},
		{"text-media", "POST", "/", fixed("ordinary") + "Content-Type: text/plain\r\n", "ordinary", 403, 403, 0},
		{"conflicting-cl", "POST", "/", "Content-Length: 22\r\nContent-Length: 23\r\nContent-Type: application/json\r\n", benign, 400, 400, 0},
		{"identical-cl", "POST", "/", "Content-Length: 22\r\nContent-Length: 22\r\nContent-Type: application/json\r\n", benign, 200, 200, 1},
		{"cl-te", "POST", "/", "Content-Length: 999\r\nTransfer-Encoding: chunked\r\nContent-Type: application/json\r\n", chunk(benign), 200, 200, 1},
		{"unsupported-te", "POST", "/", "Transfer-Encoding: gzip\r\nContent-Type: application/json\r\n", benign, 501, 501, 0},
		{"spoofed-metadata", "GET", "/", "X-Forwarded-For: 192.0.2.44\r\n", "", 200, 200, 1},
		{"response-benign", "GET", "/response-benign", "", "", 200, 200, 1},
		{"response-header", "GET", "/response-header", "", "", 406, 406, 1},
		{"response-body", "GET", "/response-body", "", "", 406, 406, 1},
	}
	for _, profile := range []string{"engine", "caddy"} {
		t.Run(profile, func(t *testing.T) {
			var mu sync.Mutex
			var effects []observation
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				b, e := io.ReadAll(io.LimitReader(r.Body, 1024))
				if e != nil {
					http.Error(w, "read failed", 500)
					return
				}
				mu.Lock()
				effects = append(effects, observation{Body: hash(b), Host: r.Host, Spoof: r.Header.Get("X-Forwarded-For") == "192.0.2.44"})
				mu.Unlock()
				w.Header().Set("Content-Type", "text/plain")
				if r.URL.Path == "/response-header" {
					w.Header().Set("X-Lab-Response", "blocked")
				}
				if r.URL.Path == "/response-body" {
					_, _ = io.WriteString(w, "aegvium-leak")
					return
				}
				_, _ = io.WriteString(w, "ordinary response")
			}))
			defer backend.Close()
			target, _ := url.Parse(backend.URL)
			tr := &http.Transport{Proxy: nil, DisableKeepAlives: true, ResponseHeaderTimeout: time.Second, DialContext: (&net.Dialer{Timeout: time.Second}).DialContext}
			defer tr.CloseIdleConnections()
			proxy := &httputil.ReverseProxy{Rewrite: func(p *httputil.ProxyRequest) {
				p.SetURL(target)
				p.Out.Host = "app.test"
				p.Out.Header.Del("X-Forwarded-For")
				if v := p.In.Header.Get("X-Forwarded-For"); v != "" {
					p.Out.Header.Set("X-Forwarded-For", v)
				}
			}, Transport: tr, ErrorLog: log.New(io.Discard, "", 0)}
			inspected, closeWAF, e := prepare(profile, directives, true, proxy)
			if e != nil {
				t.Fatal(e)
			}
			defer closeWAF()
			var current atomic.Pointer[source]
			server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				s := &source{ReadCloser: r.Body}
				current.Store(s)
				r.Body = s
				defer s.Close()
				inspected.ServeHTTP(w, r)
			}), ReadHeaderTimeout: time.Second, ReadTimeout: time.Second, WriteTimeout: 3 * time.Second, IdleTimeout: time.Second, ErrorLog: log.New(io.Discard, "", 0)}
			listener, e := net.Listen("tcp4", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			joined := make(chan error, 1)
			go func() { joined <- server.Serve(listener) }()
			defer server.Close()
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					mu.Lock()
					before := len(effects)
					mu.Unlock()
					current.Store(nil)
					input := fmt.Sprintf("%s %s HTTP/1.1\r\nHost: app.test\r\nUser-Agent: aegvium-fixture\r\nConnection: close\r\n%s\r\n%s", tc.method, tc.path, tc.headers, tc.body)
					conn, e := net.DialTimeout("tcp4", listener.Addr().String(), time.Second)
					if e != nil {
						t.Fatal(e)
					}
					defer conn.Close()
					_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
					if _, e = io.WriteString(conn, input); e != nil {
						t.Fatal(e)
					}
					if tc.name == "short-fixed" {
						if e = conn.(*net.TCPConn).CloseWrite(); e != nil {
							t.Fatal(e)
						}
					}
					response, e := http.ReadResponse(bufio.NewReader(conn), nil)
					if e != nil {
						t.Fatal(e)
					}
					data, e := io.ReadAll(io.LimitReader(response.Body, 4097))
					response.Body.Close()
					if e != nil {
						t.Fatal(e)
					}
					o := observation{Profile: profile, Case: tc.name, Input: hash([]byte(input)), Status: response.StatusCode, Response: hash(data)}
					if s := current.Load(); s != nil {
						deadline := time.Now().Add(time.Second)
						wantedClosed := int64(1)
						if profile == "caddy" && tc.backend == 1 && tc.method == "POST" {
							wantedClosed = 3
						}
						for s.closed.Load() < wantedClosed && time.Now().Before(deadline) {
							time.Sleep(time.Millisecond)
						}
						o.SourceClosed = s.closed.Load()
					}
					mu.Lock()
					o.Backend = len(effects) - before
					if o.Backend == 1 {
						effect := effects[before]
						o.Body = effect.Body
						o.Host = effect.Host
						o.Spoof = effect.Spoof
					}
					mu.Unlock()
					want := tc.engine
					if profile == "caddy" {
						want = tc.caddy
					}
					emit(t, o)
					if o.Status != want || o.Backend != tc.backend {
						t.Fatalf("status/backend got %d/%d want %d/%d", o.Status, o.Backend, want, tc.backend)
					}
					if o.Backend == 1 {
						body := tc.body
						if strings.Contains(tc.headers, "chunked") {
							body = benign
						}
						if o.Body != hash([]byte(body)) || o.Host != "app.test" || o.Spoof != (tc.name == "spoofed-metadata") {
							t.Fatal("backend byte/authority/metadata mismatch")
						}
					}
					parserRejected := tc.name == "conflicting-cl" || tc.name == "unsupported-te"
					if parserRejected && o.SourceClosed != 0 || !parserRejected && o.SourceClosed < 1 {
						t.Fatal("original source closure missing")
					}
					if tc.name == "response-body" && strings.Contains(string(data), "aegvium-leak") {
						t.Fatal("denied response leaked bytes")
					}
				})
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if e := server.Shutdown(ctx); e != nil {
				t.Fatal(e)
			}
			select {
			case e := <-joined:
				if !errors.Is(e, http.ErrServerClosed) {
					t.Fatal(e)
				}
			case <-time.After(time.Second):
				t.Fatal("server not joined")
			}
			addr := listener.Addr().String()
			c, e := net.DialTimeout("tcp4", addr, 100*time.Millisecond)
			if e == nil {
				c.Close()
				t.Fatal("ingress remains")
			}
			backend.Close()
			c, e = net.DialTimeout("tcp4", target.Host, 100*time.Millisecond)
			if e == nil {
				c.Close()
				t.Fatal("backend remains")
			}
			emit(t, map[string]any{"profile": profile, "cleanup": "verified"})
		})
	}
}

func TestConnectorRuleReload(t *testing.T) {
	for _, profile := range []string{"engine", "caddy"} {
		t.Run(profile, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "rules.conf")
			rule := func(value string) string {
				return fmt.Sprintf("SecRule REQUEST_URI \"@streq /%s\" \"id:100010,phase:1,deny,status:403,nolog\"\n", value)
			}
			write := func(value string) {
				if e := os.WriteFile(file, []byte(rule(value)), 0600); e != nil {
					t.Fatal(e)
				}
			}
			write("old")
			rules := "SecRuleEngine On\nInclude " + file + "\n"
			next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })
			first, closeFirst, e := prepare(profile, rules, false, next)
			if e != nil {
				t.Fatal(e)
			}
			defer closeFirst()
			check := func(phase string, h http.Handler, old, new int) {
				for _, tc := range []struct {
					name   string
					status int
				}{{"old", old}, {"new", new}} {
					r := httptest.NewRequest("GET", "/"+tc.name, nil)
					r.RemoteAddr = "192.0.2.1:12345"
					w := httptest.NewRecorder()
					h.ServeHTTP(w, r)
					emit(t, map[string]any{"profile": profile, "phase": phase, "case": tc.name, "status": w.Code})
					if w.Code != tc.status {
						t.Fatalf("%s/%s status %d want %d", phase, tc.name, w.Code, tc.status)
					}
				}
			}
			check("initial", first, 403, 200)
			write("new")
			same, closeSame, e := prepare(profile, rules, false, next)
			if e != nil {
				t.Fatal(e)
			}
			defer closeSame()
			old, new := 200, 403
			if profile == "caddy" {
				old, new = 403, 200
			}
			check("same-configuration", same, old, new)
			changed, closeChanged, e := prepare(profile, rules+"# explicit generation 2\n", false, next)
			if e != nil {
				t.Fatal(e)
			}
			defer closeChanged()
			check("changed-configuration", changed, 200, 403)
			_, _, e = prepare(profile, "NotACorazaDirective", false, next)
			if e == nil {
				t.Fatal("invalid rules accepted")
			}
			emit(t, map[string]any{"profile": profile, "phase": "invalid-rejected"})
			check("known-good", same, old, new)
			write("old")
			rollback, closeRollback, e := prepare(profile, rules+"# explicit rollback\n", false, next)
			if e != nil {
				t.Fatal(e)
			}
			defer closeRollback()
			check("rollback", rollback, 403, 200)
		})
	}
}
