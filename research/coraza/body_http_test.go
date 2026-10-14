// SPDX-License-Identifier: BSD-3-Clause
package spike

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
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	crs "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
	corazahttp "github.com/corazawaf/coraza/v3/http"
	"github.com/corazawaf/coraza/v3/types"
)

type bodyWireConn struct {
	net.Conn
	read atomic.Int64
}

func (c *bodyWireConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.read.Add(int64(n))
	return n, err
}

type bodyWireListener struct {
	net.Listener
	accepted chan *bodyWireConn
}

func (l *bodyWireListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	w := &bodyWireConn{Conn: c}
	l.accepted <- w
	return w, nil
}

type bodyWireReader struct {
	io.ReadCloser
	read, closed, closeError atomic.Int64
}

func (b *bodyWireReader) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	b.read.Add(int64(n))
	return n, err
}
func (b *bodyWireReader) Close() error {
	b.closed.Add(1)
	err := b.ReadCloser.Close()
	if err != nil {
		var timeout net.Error
		if errors.As(err, &timeout) && timeout.Timeout() {
			b.closeError.Store(1)
		} else {
			b.closeError.Store(2)
		}
	}
	return err
}

type bodyHTTPObservation struct {
	Case             string   `json:"case"`
	Status           int      `json:"status"`
	Handler          int      `json:"handler"`
	Backend          int      `json:"backend"`
	ContentLength    *int64   `json:"content_length"`
	TransferEncoding []string `json:"transfer_encoding"`
	HeaderLengths    []string `json:"header_lengths"`
	SourceRead       int64    `json:"source_read"`
	SourceClosed     int64    `json:"source_closed"`
	SourceCloseError string   `json:"source_close_error"`
	WireRead         int64    `json:"wire_read"`
	RequestBytes     int      `json:"request_bytes"`
	RequestSHA256    string   `json:"request_sha256"`
	BodySHA256       string   `json:"body_sha256"`
	Rules            []int    `json:"rules"`
	Phases           []int    `json:"phases"`
	ConnectionClosed bool     `json:"connection_closed"`
	ServerJoined     bool     `json:"server_joined"`
	ListenerAbsent   bool     `json:"listener_absent"`
}

func TestBodyAdmissionTCP(t *testing.T) {
	benign := `{"payload":"ordinary"}`
	script := `{"payload":"<script>alert(1)</script>"}`
	sql := url.Values{"payload": {"' OR 1=1--"}}.Encode()
	over := `{"payload":"` + strings.Repeat("x", 129-len(`{"payload":""}`)) + `"}`
	chunk := func(body string) string { return fmt.Sprintf("%x\r\n%s\r\n0\r\n\r\n", len(body), body) }
	fixed := func(body string) string { return fmt.Sprintf("Content-Length: %d\r\n", len(body)) }
	cases := []struct {
		name, framing, media, body string
		stall                      bool
		status, handler, backend   int
	}{
		{"fixed-json", fixed(benign), "application/json", benign, false, 200, 1, 1},
		{"json-script", fixed(script), "application/json", script, false, 403, 1, 0},
		{"form-sql", fixed(sql), "application/x-www-form-urlencoded", sql, false, 403, 1, 0},
		{"fixed-over", fixed(over), "application/json", over, false, 413, 1, 0},
		{"chunked-json", "Transfer-Encoding: chunked\r\n", "application/json", chunk(benign), false, 200, 1, 1},
		{"chunked-over", "Transfer-Encoding: chunked\r\n", "application/json", chunk(over), false, 413, 1, 0},
		{"short-fixed", fmt.Sprintf("Content-Length: %d\r\n", len(benign)+1), "application/json", benign, false, 500, 1, 0},
		{"bad-chunk", "Transfer-Encoding: chunked\r\n", "application/json", "gg\r\n", false, 500, 1, 0},
		{"invalid-json", fixed(`{"payload":`), "application/json", `{"payload":`, false, 400, 1, 0},
		{"text-media", fixed("ordinary"), "text/plain", "ordinary", false, 415, 1, 0},
		{"conflicting-cl", "Content-Length: 22\r\nContent-Length: 23\r\n", "application/json", benign, false, 400, 0, 0},
		{"identical-cl", "Content-Length: 22\r\nContent-Length: 22\r\n", "application/json", benign, false, 200, 1, 1},
		{"cl-te", "Content-Length: 999\r\nTransfer-Encoding: chunked\r\n", "application/json", chunk(benign), false, 200, 1, 1},
		{"unsupported-te", "Transfer-Encoding: gzip\r\n", "application/json", benign, false, 501, 0, 0},
		{"stalled-chunked", "Transfer-Encoding: chunked\r\n", "application/json", "c8\r\n" + over, true, 413, 1, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			observation := bodyHTTPObservation{Case: tc.name, SourceCloseError: "none", Rules: []int{}, Phases: []int{}}
			matches := map[int]int{}
			waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithRootFS(crs.FS).WithErrorCallback(func(m types.MatchedRule) { mu.Lock(); matches[m.Rule().ID()] = int(m.Rule().Phase()); mu.Unlock() }).WithDirectives("Include @coraza.conf-recommended\nSecRuleEngine On\nInclude @crs-setup.conf.example\nInclude @owasp_crs/*.conf\n"))
			if err != nil {
				t.Fatal(err)
			}
			base, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			listener := &bodyWireListener{Listener: base, accepted: make(chan *bodyWireConn, 1)}
			closed := make(chan struct{})
			var closeOnce sync.Once
			var bodySource *bodyWireReader
			backend := corazahttp.WrapHandler(waf, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				data, e := io.ReadAll(r.Body)
				mu.Lock()
				observation.Backend++
				if e == nil {
					sum := sha256.Sum256(data)
					observation.BodySHA256 = hex.EncodeToString(sum[:])
				}
				mu.Unlock()
				if e != nil {
					http.Error(w, "backend read error", 500)
					return
				}
				w.WriteHeader(200)
			}))
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				source := &bodyWireReader{ReadCloser: r.Body}
				mu.Lock()
				observation.Handler++
				length := r.ContentLength
				observation.ContentLength = &length
				observation.TransferEncoding = append([]string{}, r.TransferEncoding...)
				observation.HeaderLengths = append([]string{}, r.Header.Values("Content-Length")...)
				bodySource = source
				mu.Unlock()
				r.Body = source
				boundedResearchBody(backend).ServeHTTP(w, r)
			})
			server := &http.Server{Handler: handler, ReadTimeout: time.Second, ReadHeaderTimeout: time.Second, WriteTimeout: 3 * time.Second, IdleTimeout: time.Second, MaxHeaderBytes: 1024, ErrorLog: log.New(io.Discard, "", 0), ConnState: func(_ net.Conn, s http.ConnState) {
				if s == http.StateClosed {
					closeOnce.Do(func() { close(closed) })
				}
			}}
			served := make(chan error, 1)
			go func() { served <- server.Serve(listener) }()
			var cleanupOnce sync.Once
			cleanup := func() {
				cleanupOnce.Do(func() {
					ctx, cancel := context.WithTimeout(context.Background(), time.Second)
					defer cancel()
					if e := server.Shutdown(ctx); e != nil {
						t.Error(e)
						_ = server.Close()
					}
					select {
					case e := <-served:
						if !errors.Is(e, http.ErrServerClosed) {
							t.Errorf("serve exit: %v", e)
						} else {
							observation.ServerJoined = true
						}
					case <-time.After(time.Second):
						t.Error("server did not join")
					}
					c, e := net.DialTimeout("tcp4", listener.Addr().String(), 100*time.Millisecond)
					if e == nil {
						c.Close()
						t.Error("listener survived shutdown")
					} else {
						observation.ListenerAbsent = true
					}
				})
			}
			defer cleanup()
			client, err := net.DialTimeout("tcp4", listener.Addr().String(), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			_ = client.SetDeadline(time.Now().Add(4 * time.Second))
			raw := "POST /body HTTP/1.1\r\nHost: example.test\r\nUser-Agent: Aegvium synthetic research\r\nAccept: */*\r\nConnection: close\r\nContent-Type: " + tc.media + "\r\n" + tc.framing + "\r\n" + tc.body
			n, err := io.WriteString(client, raw)
			if err != nil || n != len(raw) {
				t.Fatalf("fixture write: %d %v", n, err)
			}
			if !tc.stall {
				if e := client.(*net.TCPConn).CloseWrite(); e != nil {
					t.Fatal(e)
				}
			}
			response, err := http.ReadResponse(bufio.NewReader(client), &http.Request{Method: "POST"})
			if err != nil {
				t.Fatal(err)
			}
			responseBody, err := io.ReadAll(io.LimitReader(response.Body, 4097))
			response.Body.Close()
			if err != nil || len(responseBody) > 4096 {
				t.Fatalf("response bounds: %d %v", len(responseBody), err)
			}
			select {
			case <-closed:
				observation.ConnectionClosed = true
			case <-time.After(time.Second):
				t.Fatal("connection did not close")
			}
			wire := <-listener.accepted
			mu.Lock()
			observation.Status = response.StatusCode
			if bodySource != nil {
				observation.SourceRead = bodySource.read.Load()
				observation.SourceClosed = bodySource.closed.Load()
				observation.SourceCloseError = []string{"none", "timeout", "other"}[bodySource.closeError.Load()]
			}
			for id := range matches {
				observation.Rules = append(observation.Rules, id)
			}
			sort.Ints(observation.Rules)
			for _, id := range observation.Rules {
				observation.Phases = append(observation.Phases, matches[id])
			}
			mu.Unlock()
			observation.WireRead = wire.read.Load()
			observation.RequestBytes = len(raw)
			sum := sha256.Sum256([]byte(raw))
			observation.RequestSHA256 = hex.EncodeToString(sum[:])
			cleanup()
			data, err := json.Marshal(observation)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("BODY-HTTP %s", data)
			if observation.Status != tc.status || observation.Handler != tc.handler || observation.Backend != tc.backend {
				t.Fatalf("HTTP outcome %s; want %d/%d/%d", data, tc.status, tc.handler, tc.backend)
			}
			if observation.Handler == 1 && (observation.SourceRead > 129 || observation.SourceClosed != 1) {
				t.Fatalf("source gate %s", data)
			}
			if observation.Backend == 1 {
				expected := sha256.Sum256([]byte(benign))
				if observation.BodySHA256 != hex.EncodeToString(expected[:]) {
					t.Fatalf("admitted body mismatch: %s", data)
				}
			}
			if tc.name == "json-script" || tc.name == "form-sql" {
				family := 941
				if tc.name == "form-sql" {
					family = 942
				}
				found := false
				for _, id := range observation.Rules {
					if id/1000 == family {
						found = true
					}
				}
				if !found {
					t.Fatalf("wire attack lacks family evidence: %s", data)
				}
			}
			if tc.stall && observation.SourceCloseError != "timeout" {
				t.Fatalf("stalled source Close classification: %s", data)
			}
			if !observation.ConnectionClosed || !observation.ServerJoined || !observation.ListenerAbsent {
				t.Fatalf("cleanup gates: %s", data)
			}
		})
	}
}
