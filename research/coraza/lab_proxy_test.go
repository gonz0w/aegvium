// SPDX-License-Identifier: BSD-3-Clause
package spike

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestLabProxyHandler(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	var last string
	var forwarded http.Header
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		mu.Lock()
		calls++
		last = string(data)
		forwarded = r.Header.Clone()
		mu.Unlock()
		if r.URL.Path == "/large" {
			_, _ = io.WriteString(w, strings.Repeat("x", LabBodyLimit+1))
			return
		}
		_, _ = io.WriteString(w, "lab backend\n")
	}))
	defer backend.Close()
	handler, transport, closer, e := labHandler(strings.TrimPrefix(backend.URL, "http://"), labDirectives)
	if e != nil {
		t.Fatal(e)
	}
	defer transport.CloseIdleConnections()
	defer closer.Close()
	cases := []struct {
		name, method, path, media, body, host string
		status, delta                         int
	}{
		{"get", "GET", "/ok", "", "", "app.test", 200, 1}, {"json", "POST", "/body", "application/json", `{"payload":"ordinary"}`, "app.test", 200, 1},
		{"script", "POST", "/body", "application/json", `{"payload":"<script>alert(1)</script>"}`, "app.test", 403, 0}, {"sql", "GET", "/?payload=%27+OR+1%3D1--", "", "", "app.test", 403, 0},
		{"unknown", "GET", "/ok", "", "", "other.test", 421, 0}, {"over", "POST", "/body", "application/json", strings.Repeat("x", LabBodyLimit+1), "app.test", 413, 0},
		{"media", "POST", "/body", "text/plain", "ordinary", "app.test", 415, 0}, {"method", "CONNECT", "/ok", "", "", "app.test", 405, 0},
		{"large-response", "GET", "/large", "", "", "app.test", 502, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, "http://app.test"+tc.path, strings.NewReader(tc.body))
			r.URL.Scheme = ""
			r.URL.Host = ""
			r.Host = tc.host
			r.RequestURI = tc.path
			r.Header.Set("Accept", "*/*")
			r.Header.Set("User-Agent", "Aegvium owned lab")
			if tc.media != "" {
				r.Header.Set("Content-Type", tc.media)
			}
			r.Header.Set("Forwarded", "for=192.0.2.99")
			r.Header.Set("X-Forwarded-For", "192.0.2.99")
			r.Header.Set("X-Real-IP", "192.0.2.99")
			r.Header.Set("X-Original-URL", "/hidden")
			mu.Lock()
			before := calls
			mu.Unlock()
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			mu.Lock()
			defer mu.Unlock()
			if w.Code != tc.status || calls-before != tc.delta {
				t.Fatalf("status%d calls%d want%d/%d", w.Code, calls-before, tc.status, tc.delta)
			}
			if tc.delta == 1 {
				if last != tc.body {
					t.Fatal("body changed")
				}
				for _, k := range []string{"Forwarded", "X-Forwarded-For", "X-Real-IP", "X-Original-URL"} {
					if forwarded.Get(k) != "" {
						t.Fatal("spoofed metadata forwarded")
					}
				}
			}
		})
	}
	backend.Close()
	r := httptest.NewRequest("GET", "/lost", nil)
	r.Host = "app.test"
	r.Header.Set("Accept", "*/*")
	r.Header.Set("User-Agent", "Aegvium owned lab")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != 502 {
		t.Fatalf("backend loss %d", w.Code)
	}
}
func TestLabProxyLifecycle(t *testing.T) {
	p := LabProfile{DataAddress: "127.0.0.1:0", HealthAddress: "127.0.0.1:0", BackendAddress: "127.0.0.1:1", Ingress: netip.MustParseAddrPort("127.0.0.1:18120")}
	if _, e := startLabProxy(p, "NotARealDirective on"); e == nil {
		t.Fatal("invalid rules accepted")
	}
	bad := p
	bad.BackendAddress = "example.com:80"
	if _, e := StartLabProxy(bad); e == nil {
		t.Fatal("nonliteral backend accepted")
	}
	f, e := StartLabProxy(p)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	client := &http.Client{Timeout: time.Second}
	request, _ := http.NewRequest("HEAD", "http://"+f.HealthAddr+"/ready", nil)
	response, e := client.Do(request)
	if e != nil {
		t.Fatal(e)
	}
	response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatal("not ready")
	}
	if e = f.Close(); e != nil {
		t.Fatal(e)
	}
	if e = f.Close(); e != nil {
		t.Fatal(e)
	}
	for _, a := range []string{f.DataAddr, f.HealthAddr} {
		c, e := net.DialTimeout("tcp4", a, 100*time.Millisecond)
		if e == nil {
			c.Close()
			t.Fatal("listener survived")
		}
	}
}
