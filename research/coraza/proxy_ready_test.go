// SPDX-License-Identifier: BSD-3-Clause
package spike

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

func TestProxyReady(t *testing.T) {
	for _, name := range []string{"transitions", "head", "route", "method", "nil", "close", "accept-failure", "server-bounds"} {
		t.Run(name, func(t *testing.T) {
			base, receiver, engine := proxyListenerFixture(t)
			handler := proxyReadyHandler(receiver)
			check := func(method, target string, code int, body string) {
				t.Helper()
				request := httptest.NewRequest(method, target, nil)
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, request)
				if response.Code != code || response.Body.String() != body || response.Header().Get("Cache-Control") != "no-store" {
					t.Fatalf("health response: code=%d body=%q cache=%q", response.Code, response.Body.String(), response.Header().Get("Cache-Control"))
				}
				if code == 405 && response.Header().Get("Allow") != "GET, HEAD" {
					t.Fatal("missing allowed methods")
				}
			}
			switch name {
			case "transitions":
				engine.Store(false)
				check("GET", "/ready", 503, "unavailable\n")
				engine.Store(true)
				check("GET", "/ready", 200, "ready\n")
				engine.Store(false)
				check("GET", "/ready", 503, "unavailable\n")
				engine.Store(true)
				check("GET", "/ready", 200, "ready\n")
			case "head":
				check("HEAD", "/ready", 200, "")
				engine.Store(false)
				check("HEAD", "/ready", 503, "")
				check("HEAD", "/unknown", 404, "")
			case "route":
				for _, target := range []string{"/", "/ready/", "/ready?x=1", "/ready?", "/READY"} {
					check("GET", target, 404, "not found\n")
				}
			case "method":
				for _, method := range []string{"POST", "PUT", "DELETE", "OPTIONS"} {
					check(method, "/ready", 405, "method not allowed\n")
				}
			case "nil":
				handler = proxyReadyHandler(nil)
				check("GET", "/ready", 503, "unavailable\n")
			case "close":
				proxyCloseListener(t, receiver)
				check("GET", "/ready", 503, "unavailable\n")
			case "accept-failure":
				_ = base.Close()
				proxyAwait(t, func() bool { return !receiver.Ready() })
				check("GET", "/ready", 503, "unavailable\n")
			case "server-bounds":
				s := proxyReadyServer(receiver)
				if s.ReadHeaderTimeout != time.Second || s.ReadTimeout != 2*time.Second || s.WriteTimeout != 2*time.Second || s.IdleTimeout != time.Second || s.MaxHeaderBytes != 4096 {
					t.Fatal("unbounded server profile")
				}
			}
			if base.accepted.Load() != 0 {
				t.Fatal("health request touched data accept path")
			}
		})
	}
}

func TestProxyReadyTCP(t *testing.T) {
	if runtime.GOOS != "openbsd" || os.Getenv("AEGVIUM_NATIVE_REPEAT") != "1" {
		t.Skip("requires owned native OpenBSD repeat")
	}
	for _, name := range []string{"lifecycle", "accept-failure"} {
		t.Run(name, func(t *testing.T) {
			data, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = data.Close() })
			engine := new(atomic.Bool)
			receiver, err := newProxyV1Listener(data, proxyExpected, time.Second, 2, engine)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = receiver.Close() })
			health, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = health.Close() })
			if data.Addr().String() == health.Addr().String() {
				t.Fatal("health and data share address")
			}
			server := proxyReadyServer(receiver)
			done := make(chan error, 1)
			go func() { done <- server.Serve(health) }()
			t.Cleanup(func() { _ = server.Close() })
			probe := func(code int) {
				t.Helper()
				c, e := net.DialTimeout("tcp4", health.Addr().String(), time.Second)
				if e != nil {
					t.Fatal(e)
				}
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				if _, e = io.WriteString(c, "HEAD /ready HTTP/1.0\r\n\r\n"); e != nil {
					t.Fatal(e)
				}
				reader := bufio.NewReader(c)
				response, e := http.ReadResponse(reader, &http.Request{Method: "HEAD"})
				if e != nil {
					t.Fatal(e)
				}
				body, e := io.ReadAll(response.Body)
				_ = response.Body.Close()
				if e != nil || response.StatusCode != code || len(body) != 0 || response.Header.Get("Cache-Control") != "no-store" {
					t.Fatalf("bare HTTP/1.0 HEAD: code=%d body=%q error=%v", response.StatusCode, body, e)
				}
				n, wireErr := reader.Read(make([]byte, 1))
				if n != 0 || !errors.Is(wireErr, io.EOF) {
					t.Fatalf("HEAD wire tail: bytes=%d error=%v", n, wireErr)
				}
			}
			probe(503)
			engine.Store(true)
			probe(200)
			if name == "lifecycle" {
				engine.Store(false)
				probe(503)
				engine.Store(true)
				probe(200)
				// The strict data role must still reject a bare health probe.
				c, e := net.DialTimeout("tcp4", data.Addr().String(), time.Second)
				if e != nil {
					t.Fatal(e)
				}
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				_, e = io.WriteString(c, "HEAD /ready HTTP/1.0\r\n\r\n")
				if e != nil {
					_ = c.Close()
					t.Fatal(e)
				}
				n, e := c.Read(make([]byte, 1))
				_ = c.Close()
				if n != 0 || e == nil {
					t.Fatal("data listener admitted bare HEAD")
				}
				if timeout, ok := e.(net.Error); ok && timeout.Timeout() {
					t.Fatal("bare HEAD timed out rather than rejected")
				}
				proxyCloseListener(t, receiver)
			} else {
				_ = data.Close()
				proxyAwait(t, func() bool { return !receiver.Ready() })
				proxyCloseListener(t, receiver)
			}
			probe(503) // Health remains reachable but cannot hide a closed/failed receiver.
			if err = server.Close(); err != nil {
				t.Fatal(err)
			}
			select {
			case err = <-done:
				if !errors.Is(err, http.ErrServerClosed) {
					t.Fatal(err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("health server did not join")
			}
			for _, address := range []string{data.Addr().String(), health.Addr().String()} {
				c, e := net.DialTimeout("tcp4", address, time.Second)
				if e == nil {
					_ = c.Close()
					t.Fatal("closed listener remained reachable")
				}
			}
			t.Log("health-close server-joined=true data-and-health-absence=verified")
		})
	}
}
