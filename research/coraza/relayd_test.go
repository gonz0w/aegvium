// SPDX-License-Identifier: BSD-3-Clause
package spike

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/corazawaf/coraza/v3"
)

// Only the owned guest controller admits this connected fixture.
func TestRelaydTraffic(t *testing.T) {
	if os.Getenv("AEGVIUM_RELAYD_TRAFFIC") != "owned-guest" || runtime.GOOS != "openbsd" {
		t.Skip("connected relayd fixture requires the owned OpenBSD guest; no host evidence")
	}
	if os.Getuid() == 0 {
		t.Fatal("traffic fixture must run as nonroot")
	}
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(rules))
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var received []string
	snapshot := func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), received...)
	}
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 128))
		if err != nil {
			http.Error(w, "fixture body read failed", 500)
			return
		}
		mu.Lock()
		received = append(received, r.Method+" "+r.URL.Path+" "+string(body))
		mu.Unlock()
		w.WriteHeader(200)
		_, _ = w.Write([]byte("synthetic backend\n"))
	})
	start := func(t *testing.T, address string, handler http.Handler) *http.Server {
		listener, err := net.Listen("tcp4", address)
		if err != nil {
			t.Fatal(err)
		}
		server := &http.Server{Addr: listener.Addr().String(), Handler: handler,
			ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 3 * time.Second,
			WriteTimeout: 3 * time.Second, IdleTimeout: time.Second, MaxHeaderBytes: 4096}
		t.Cleanup(func() { _ = server.Close() })
		go func() {
			if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
				t.Errorf("fixture server: %v", err)
			}
		}()
		return server
	}
	backendServer := start(t, "127.0.0.1:0", backend)
	target, err := url.Parse("http://" + backendServer.Addr)
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true,
		DialContext:           (&net.Dialer{Timeout: 2 * time.Second}).DialContext,
		ResponseHeaderTimeout: 2 * time.Second}
	t.Cleanup(transport.CloseIdleConnections)
	proxy := &httputil.ReverseProxy{
		Rewrite:   func(r *httputil.ProxyRequest) { r.SetURL(target) },
		Transport: transport,
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			http.Error(w, "fixture backend unavailable", 502)
		},
	}
	inspected := explicitFailure(waf, proxy)
	inspectionHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/_aegvium/ready" {
			if r.Method != http.MethodHead {
				w.WriteHeader(405)
				return
			}
			w.WriteHeader(200)
			return
		}
		inspected.ServeHTTP(w, r)
	})
	inspection := start(t, "127.0.0.1:18081", inspectionHandler)
	clientTransport := &http.Transport{Proxy: nil, DisableKeepAlives: true}
	t.Cleanup(clientTransport.CloseIdleConnections)
	client := &http.Client{Transport: clientTransport, Timeout: 3 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	send := func(base, method, path, body string) (int, string, error) {
		req, err := http.NewRequestWithContext(context.Background(), method, base+path, strings.NewReader(body))
		if err != nil {
			return 0, "", err
		}
		req.Host = "fixture.test"
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		response, err := client.Do(req)
		if err != nil {
			return 0, "", err
		}
		defer response.Body.Close()
		data, err := io.ReadAll(io.LimitReader(response.Body, 4096))
		return response.StatusCode, string(data), err
	}
	ready := func(t *testing.T) {
		before := len(snapshot())
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) {
			status, _, err := send("http://127.0.0.1:18080", "HEAD", "/_aegvium/ready", "")
			if err == nil && status == 200 {
				if len(snapshot()) != before {
					t.Fatal("readiness reached synthetic backend")
				}
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatal("relayd readiness deadline exceeded")
	}
	ready(t)
	for _, arm := range []struct{ name, base string }{
		{"direct", "http://127.0.0.1:18081"}, {"relayd", "http://127.0.0.1:18080"},
	} {
		for _, tc := range []struct {
			name, method, path, body string
			status, count            int
		}{
			{"benign-get", "GET", "/allowed", "", 200, 1},
			{"benign-post", "POST", "/allowed", "payload=ordinary", 200, 1},
			{"uri-denied", "GET", "/forbidden", "", 403, 0},
			{"body-denied", "POST", "/allowed", "payload=forbidden", 403, 0},
		} {
			t.Run(arm.name+"-"+tc.name, func(t *testing.T) {
				before := len(snapshot())
				status, body, err := send(arm.base, tc.method, tc.path, tc.body)
				got := snapshot()[before:]
				if err != nil || status != tc.status || len(got) != tc.count {
					t.Fatalf("status=%d receipts=%v err=%v; want %d/%d", status, got, err, tc.status, tc.count)
				}
				if tc.count == 1 && (got[0] != tc.method+" "+tc.path+" "+tc.body || body != "synthetic backend\n") {
					t.Fatalf("backend bytes/response mismatch: receipt=%q response=%q", got[0], body)
				}
			})
		}
	}
	t.Run("inspection-loss", func(t *testing.T) {
		before := len(snapshot())
		connection, err := net.DialTimeout("tcp4", backendServer.Addr, time.Second)
		if err != nil {
			t.Fatalf("synthetic backend was not alive before inspection loss: %v", err)
		}
		_ = connection.Close()
		if err := inspection.Close(); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 3; i++ {
			status, _, err := send("http://127.0.0.1:18080", "GET", "/allowed", "")
			if err == nil && status < 400 {
				t.Fatalf("inspection loss returned success status %d", status)
			}
			t.Logf("loss attempt %d: status=%d transport-error=%t", i+1, status, err != nil)
			time.Sleep(500 * time.Millisecond)
		}
		if len(snapshot()) != before {
			t.Fatal("inspection loss forwarded to backend")
		}
	})
	t.Run("recovery", func(t *testing.T) {
		inspection = start(t, "127.0.0.1:18081", inspectionHandler)
		ready(t)
		before := len(snapshot())
		status, body, err := send("http://127.0.0.1:18080", "POST", "/allowed", "payload=recovered")
		got := snapshot()[before:]
		if err != nil || status != 200 || body != "synthetic backend\n" || len(got) != 1 || got[0] != "POST /allowed payload=recovered" {
			t.Fatalf("recovery status=%d receipts=%v response=%q err=%v", status, got, body, err)
		}
	})
}
