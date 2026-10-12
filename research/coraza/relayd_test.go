// SPDX-License-Identifier: BSD-3-Clause
package spike

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
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
	type inspectionConnectionKey struct{}
	type inspectionEvent struct {
		Connection   int    `json:"connection,omitempty"`
		Milliseconds int64  `json:"milliseconds"`
		Kind         string `json:"kind"`
		Method       string `json:"method,omitempty"`
		Path         string `json:"path,omitempty"`
	}
	type wireObservation struct {
		Connection   int    `json:"connection"`
		Milliseconds int64  `json:"milliseconds"`
		Bytes        int    `json:"bytes"`
		SHA256       string `json:"sha256"`
		AllowedGET   int    `json:"allowed_get_markers"`
		ForbiddenGET int    `json:"forbidden_get_markers"`
		ReadyHEAD    int    `json:"ready_head_markers"`
		Close        int    `json:"connection_close_markers"`
		Overflow     bool   `json:"overflow"`
	}
	var eventMu sync.Mutex
	var wireEvents []wireObservation
	var nextConnection int
	var events []inspectionEvent
	var eventOverflow bool
	t.Cleanup(func() {
		eventMu.Lock()
		overflow := eventOverflow
		eventMu.Unlock()
		if overflow {
			t.Error("inspection diagnostics overflowed")
		}
	})
	eventStart := time.Now()
	recordEvent := func(kind, method, path string, connection int) {
		eventMu.Lock()
		defer eventMu.Unlock()
		if len(events) >= 1024 {
			eventOverflow = true
			return
		}
		events = append(events, inspectionEvent{connection, time.Since(eventStart).Milliseconds(), kind, method, path})
	}
	eventSnapshot := func() ([]inspectionEvent, bool) {
		eventMu.Lock()
		defer eventMu.Unlock()
		return append([]inspectionEvent(nil), events...), eventOverflow
	}
	observeWire := func(connection int, data []byte, overflow bool) {
		eventMu.Lock()
		defer eventMu.Unlock()
		if len(wireEvents) >= 1024 || overflow {
			eventOverflow = true
		}
		if len(wireEvents) >= 1024 {
			return
		}
		wireEvents = append(wireEvents, wireObservation{
			connection, time.Since(eventStart).Milliseconds(), len(data), fmt.Sprintf("%x", sha256.Sum256(data)),
			bytes.Count(data, []byte("GET /allowed HTTP/1.1\r\n")), bytes.Count(data, []byte("GET /forbidden HTTP/1.1\r\n")),
			bytes.Count(data, []byte("HEAD /_aegvium/ready HTTP/1.1\r\n")), bytes.Count(bytes.ToLower(data), []byte("connection: close\r\n")), overflow})
	}
	wireSnapshot := func() []wireObservation {
		eventMu.Lock()
		defer eventMu.Unlock()
		return append([]wireObservation(nil), wireEvents...)
	}
	start := func(t *testing.T, address string, handler http.Handler, idle time.Duration) *http.Server {
		listener, err := net.Listen("tcp4", address)
		if err != nil {
			t.Fatal(err)
		}
		if address == "127.0.0.1:18081" {
			listener = &inspectionReadListener{Listener: listener, wrap: func(conn net.Conn) net.Conn {
				eventMu.Lock()
				nextConnection++
				id := nextConnection
				eventMu.Unlock()
				return &inspectionReadConn{Conn: conn, id: id, observe: observeWire}
			}}
		}
		server := &http.Server{Addr: listener.Addr().String(), Handler: handler,
			ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 3 * time.Second,
			WriteTimeout: 3 * time.Second, IdleTimeout: idle, MaxHeaderBytes: 4096}
		if address == "127.0.0.1:18081" {
			server.ConnState = func(conn net.Conn, state http.ConnState) {
				recordEvent("connection-"+state.String(), "", "", conn.(*inspectionReadConn).id)
			}
			server.ConnContext = func(ctx context.Context, conn net.Conn) context.Context {
				return context.WithValue(ctx, inspectionConnectionKey{}, conn.(*inspectionReadConn).id)
			}
		}
		t.Cleanup(func() { _ = server.Close() })
		go func() {
			if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
				t.Errorf("fixture server: %v", err)
			}
		}()
		return server
	}
	backendServer := start(t, "127.0.0.1:0", backend, time.Second)
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
		recordEvent("application-arrival", r.Method, r.URL.Path, r.Context().Value(inspectionConnectionKey{}).(int))
		inspected.ServeHTTP(w, r)
	})
	inspection := start(t, "127.0.0.1:18081", inspectionHandler, time.Second)
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
			if strings.HasSuffix(arm.name, "-longidle") && tc.name != "pipeline-denied-benign" && tc.name != "pipeline-benign-benign" && tc.name != "serialized-denied-benign" {
				continue
			}
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

	// Raw request bytes preserve framing that a normal HTTP client would normalize.
	for _, arm := range []struct{ name, address string }{
		{"direct", "127.0.0.1:18081"}, {"relayd", "127.0.0.1:18080"},
		{"direct-longidle", "127.0.0.1:18081"}, {"relayd-longidle", "127.0.0.1:18080"},
	} {
		if arm.name == "direct-longidle" {
			if err := inspection.Close(); err != nil {
				t.Fatal(err)
			}
			inspection = start(t, "127.0.0.1:18081", inspectionHandler, 3*time.Second)
			ready(t)
		}
		chunked := func(body string) string { return fmt.Sprintf("%x\r\n%s\r\n0\r\n\r\n", len(body), body) }
		post := "POST /allowed HTTP/1.1\r\nHost: fixture.test\r\nContent-Type: application/x-www-form-urlencoded\r\nConnection: close\r\n"
		for _, tc := range []struct {
			name, wire, receipt string
			statuses            []int
			reject              bool
			serial              bool
			wake                bool
		}{
			{"chunked-benign", post + "Transfer-Encoding: chunked\r\n\r\n" + chunked("payload=ordinary"), "POST /allowed payload=ordinary", []int{200}, false, false, false},
			{"chunked-denied", post + "Transfer-Encoding: chunked\r\n\r\n" + chunked("payload=forbidden"), "", []int{403}, false, false, false},
			{"conflicting-length", post + "Content-Length: 16\r\nContent-Length: 17\r\n\r\npayload=ordinary", "", nil, true, false, false},
			{"mixed-framing-attack", post + "Content-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n" + chunked("payload=forbidden"), "", nil, true, false, false},
			{"pipeline-denied-benign", "GET /forbidden HTTP/1.1\r\nHost: fixture.test\r\n\r\nGET /allowed HTTP/1.1\r\nHost: fixture.test\r\nConnection: close\r\n\r\n", "GET /allowed ", []int{403, 200}, false, false, false},
			{"pipeline-benign-benign", "GET /allowed HTTP/1.1\r\nHost: fixture.test\r\n\r\nGET /allowed HTTP/1.1\r\nHost: fixture.test\r\nConnection: close\r\n\r\n", "GET /allowed ", []int{200, 200}, false, false, false},
			{"serialized-denied-benign", "GET /forbidden HTTP/1.1\r\nHost: fixture.test\r\n\r\nGET /allowed HTTP/1.1\r\nHost: fixture.test\r\nConnection: close\r\n\r\n", "GET /allowed ", []int{403, 200}, false, true, false},
			{"wake-pipeline-denied-benign", "GET /forbidden HTTP/1.1\r\nHost: fixture.test\r\n\r\nGET /allowed HTTP/1.1\r\nHost: fixture.test\r\nConnection: close\r\n\r\n", "GET /allowed ", []int{403, 200}, false, false, true},
			{"wake-pipeline-benign-benign", "GET /allowed HTTP/1.1\r\nHost: fixture.test\r\n\r\nGET /allowed HTTP/1.1\r\nHost: fixture.test\r\nConnection: close\r\n\r\n", "GET /allowed ", []int{200, 200}, false, false, true},
		} {
			if strings.HasSuffix(arm.name, "-longidle") && tc.name != "pipeline-denied-benign" && tc.name != "pipeline-benign-benign" && tc.name != "serialized-denied-benign" {
				continue
			}
			t.Run(arm.name+"-"+tc.name, func(t *testing.T) {
				before := len(snapshot())
				initialEvents, _ := eventSnapshot()
				initialWireEvents := wireSnapshot()
				connection, err := net.DialTimeout("tcp4", arm.address, time.Second)
				if err != nil {
					t.Fatal(err)
				}
				defer connection.Close()
				if err := connection.SetDeadline(time.Now().Add(6 * time.Second)); err != nil {
					t.Fatal(err)
				}
				wire := tc.wire
				var secondWire string
				if tc.serial {
					parts := strings.SplitN(wire, "GET /allowed", 2)
					wire, secondWire = parts[0], "GET /allowed"+parts[1]
				}
				written, err := io.WriteString(connection, wire)
				if err != nil || written != len(wire) {
					t.Fatalf("raw initial write: bytes=%d want=%d err=%v", written, len(wire), err)
				}
				t.Logf("client-wire bytes=%d sha256=%x", written, sha256.Sum256([]byte(wire)))
				reader := bufio.NewReader(connection)
				var statuses []int
				var readError error
				t.Cleanup(func() {
					got := snapshot()[before:]
					hostile := 0
					for _, receipt := range got {
						if strings.Contains(receipt, "/forbidden") {
							hostile++
						}
					}
					eventList, overflow := eventSnapshot()
					data, err := json.Marshal(eventList[len(initialEvents):])
					if err != nil || overflow {
						t.Fatalf("inspection diagnostics incomplete: overflow=%t err=%v", overflow, err)
					}
					t.Logf("inspection-events %s", data)
					wireData, err := json.Marshal(wireSnapshot()[len(initialWireEvents):])
					if err != nil {
						t.Fatal(err)
					}
					t.Logf("inspection-wire %s", wireData)
					t.Logf("raw-observation statuses=%v backend-count=%d hostile-uri-count=%d read-error=%v", statuses, len(got), hostile, readError)
				})
				responses := len(tc.statuses)
				if tc.reject {
					responses = 1
				}
				for i := 0; i < responses; i++ {
					if i == 1 && (tc.serial || tc.wake) {
						if tc.wake {
							secondWire = "\r\n"
						}
						written, err := io.WriteString(connection, secondWire)
						if err != nil || written != len(secondWire) {
							readError = err
							t.Fatalf("raw second write: bytes=%d want=%d err=%v", written, len(secondWire), err)
						}
						t.Logf("client-wire bytes=%d sha256=%x", written, sha256.Sum256([]byte(secondWire)))
					}
					response, err := http.ReadResponse(reader, &http.Request{Method: "POST"})
					if err != nil {
						readError = err
						break
					}
					statuses = append(statuses, response.StatusCode)
					body, err := io.ReadAll(io.LimitReader(response.Body, 4097))
					_ = response.Body.Close()
					if err != nil || len(body) > 4096 {
						t.Fatalf("raw response body exceeded bound or failed: size=%d err=%v", len(body), err)
					}
				}
				if tc.reject {
					// A bounded wait ending in timeout is not proof of safe rejection.
					if readError != nil && !errors.Is(readError, io.EOF) && !errors.Is(readError, io.ErrUnexpectedEOF) {
						t.Fatalf("inconclusive malformed-framing result: %v", readError)
					}
					if len(statuses) > 0 && statuses[0] < 400 {
						t.Fatalf("malformed framing returned success: %v", statuses)
					}
					time.Sleep(250 * time.Millisecond)
				} else {
					if readError != nil || len(statuses) != len(tc.statuses) {
						t.Fatalf("raw statuses=%v read-error=%v; want %v", statuses, readError, tc.statuses)
					}
					for i := range statuses {
						if statuses[i] != tc.statuses[i] {
							t.Fatalf("raw statuses=%v; want %v", statuses, tc.statuses)
						}
					}
				}
				got := snapshot()[before:]
				if tc.receipt == "" {
					if len(got) != 0 {
						t.Fatalf("raw rejected request reached backend: %v", got)
					}
				} else {
					wantCount := 1
					if strings.HasSuffix(tc.name, "pipeline-benign-benign") {
						wantCount = 2
					}
					if len(got) != wantCount {
						t.Fatalf("raw backend bytes=%v; want %d receipts of %q", got, wantCount, tc.receipt)
					}
					for _, receipt := range got {
						if receipt != tc.receipt {
							t.Fatalf("raw backend bytes=%v; want exactly %q", got, tc.receipt)
						}
					}
				}
				t.Logf("framing statuses=%v backend-count=%d closed=%t", statuses, len(got), readError != nil)
			})
		}
	}

	if err := inspection.Close(); err != nil {
		t.Fatal(err)
	}
	inspection = start(t, "127.0.0.1:18081", inspectionHandler, time.Second)
	ready(t)
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
		inspection = start(t, "127.0.0.1:18081", inspectionHandler, time.Second)
		ready(t)
		before := len(snapshot())
		status, body, err := send("http://127.0.0.1:18080", "POST", "/allowed", "payload=recovered")
		got := snapshot()[before:]
		if err != nil || status != 200 || body != "synthetic backend\n" || len(got) != 1 || got[0] != "POST /allowed payload=recovered" {
			t.Fatalf("recovery status=%d receipts=%v response=%q err=%v", status, got, body, err)
		}
	})
}

// Test-only recording at the inspection Read boundary; no bytes are changed.
type inspectionReadListener struct {
	net.Listener
	wrap func(net.Conn) net.Conn
}

func (l *inspectionReadListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return l.wrap(conn), nil
}

type inspectionReadConn struct {
	net.Conn
	id       int
	mu       sync.Mutex
	captured []byte
	overflow bool
	observe  func(int, []byte, bool)
}

func (c *inspectionReadConn) Read(buffer []byte) (int, error) {
	n, err := c.Conn.Read(buffer)
	if n > 0 {
		c.mu.Lock()
		remaining := 8192 - len(c.captured)
		count := n
		if count > remaining {
			count = remaining
			c.overflow = true
		}
		c.captured = append(c.captured, buffer[:count]...)
		data, overflow := append([]byte(nil), c.captured...), c.overflow
		c.mu.Unlock()
		c.observe(c.id, data, overflow)
	}
	return n, err
}
func TestInspectionReadRecorder(t *testing.T) {
	for _, size := range []int{150, 9000} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			left, right := net.Pipe()
			defer left.Close()
			payload := bytes.Repeat([]byte("x"), size)
			var final []byte
			var overflow bool
			conn := &inspectionReadConn{Conn: left, id: 7, observe: func(id int, data []byte, exceeded bool) {
				if id != 7 {
					t.Errorf("connection identity changed")
				}
				final, overflow = data, exceeded
			}}
			done := make(chan error, 1)
			go func() { _, err := right.Write(payload); _ = right.Close(); done <- err }()
			buffer := make([]byte, 31)
			var got []byte
			for {
				n, err := conn.Read(buffer)
				got = append(got, buffer[:n]...)
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			want := size
			if want > 8192 {
				want = 8192
			}
			if !bytes.Equal(got, payload) || !bytes.Equal(final, payload[:want]) || overflow != (size > 8192) {
				t.Fatal("read bytes or bounded recording mismatch")
			}
		})
	}
}
