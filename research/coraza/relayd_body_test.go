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
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	crs "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
	corazahttp "github.com/corazawaf/coraza/v3/http"
	"github.com/corazawaf/coraza/v3/types"
)

func TestRelaydBodyComparison(t *testing.T) {
	if os.Getenv("AEGVIUM_RELAYD_BODY") != "owned-guest" || runtime.GOOS != "openbsd" {
		t.Skip("owned OpenBSD relayd body fixture required")
	}
	arms := []string{"direct", "http", "tcp"}

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
		{"fixed-json-halfclose", fixed(benign), "application/json", benign, false, 200, 1, 1},
		{"chunked-json-halfclose", "Transfer-Encoding: chunked\r\n", "application/json", chunk(benign), false, 200, 1, 1},
		{"json-script-halfclose", fixed(script), "application/json", script, false, 403, 1, 0},
		{"fixed-over-halfclose", fixed(over), "application/json", over, false, 413, 1, 0},
		{"chunked-over-halfclose", "Transfer-Encoding: chunked\r\n", "application/json", chunk(over), false, 413, 1, 0},
		{"conflicting-cl-halfclose", "Content-Length: 22\r\nContent-Length: 23\r\n", "application/json", benign, false, 400, 0, 0},
		{"short-open", fmt.Sprintf("Content-Length: %d\r\n", len(benign)+1), "application/json", benign, false, 500, 1, 0},
	}
	for _, arm := range arms {
		for _, tc := range cases {
			t.Run(arm+"/"+tc.name, func(t *testing.T) {
				var mu sync.Mutex
				observation := bodyHTTPObservation{Case: arm + "/" + tc.name, SourceCloseError: "none", Rules: []int{}, Phases: []int{}}
				matches := map[int]int{}
				waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithRootFS(crs.FS).WithErrorCallback(func(m types.MatchedRule) { mu.Lock(); matches[m.Rule().ID()] = int(m.Rule().Phase()); mu.Unlock() }).WithDirectives("Include @coraza.conf-recommended\nSecRuleEngine On\nInclude @crs-setup.conf.example\nInclude @owasp_crs/*.conf\n"))
				if err != nil {
					t.Fatal(err)
				}
				address := "127.0.0.1:0"
				if arm != "direct" {
					address = "127.0.0.1:18081"
				}
				base, err := net.Listen("tcp4", address)
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
				target := listener.Addr().String()
				if arm == "http" {
					target = "127.0.0.1:18080"
				}
				if arm == "tcp" {
					target = "127.0.0.1:18082"
				}
				client, err := net.DialTimeout("tcp4", target, time.Second)
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
				writeShutdown := tc.name == "short-fixed" || strings.HasSuffix(tc.name, "-halfclose")
				if writeShutdown {
					if e := client.(*net.TCPConn).CloseWrite(); e != nil {
						t.Fatal(e)
					}
				}
				response, responseErr := http.ReadResponse(bufio.NewReader(client), &http.Request{Method: "POST"})
				status := 0
				responseError := "none"
				if responseErr == nil {
					status = response.StatusCode
					responseBody, e := io.ReadAll(io.LimitReader(response.Body, 4097))
					response.Body.Close()
					if e != nil || len(responseBody) > 4096 {
						t.Fatalf("response bounds: %d %v", len(responseBody), e)
					}
				} else {
					var timeout net.Error
					if errors.Is(responseErr, io.EOF) {
						responseError = "eof"
					} else if errors.As(responseErr, &timeout) && timeout.Timeout() {
						responseError = "timeout"
					} else {
						responseError = "other"
					}
				}
				client.Close()
				cleanup()
				// Shutdown joins all accepted handlers/connections; a relayd parser rejection may create none.
				observation.ConnectionClosed = true
				wireRead := int64(0)
				select {
				case wire := <-listener.accepted:
					wireRead = wire.read.Load()
					select {
					case <-closed:
					default:
						t.Error("accepted inspection connection survived shutdown")
					}
				default:
				}
				mu.Lock()
				observation.Status = status
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
				observation.WireRead = wireRead
				observation.RequestBytes = len(raw)
				sum := sha256.Sum256([]byte(raw))
				observation.RequestSHA256 = hex.EncodeToString(sum[:])
				cleanup()
				data, err := json.Marshal(observation)
				if err != nil {
					t.Fatal(err)
				}
				t.Logf("RELAYD-BODY %s", data)
				t.Logf("RELAYD-BODY-ERROR %s %s", observation.Case, responseError)
				lifecycle, e := json.Marshal(struct {
					Case          string `json:"case"`
					WriteShutdown bool   `json:"write_shutdown"`
					BytesSent     int    `json:"bytes_sent"`
				}{observation.Case, writeShutdown, n})
				if e != nil {
					t.Fatal(e)
				}
				t.Logf("RELAYD-BODY-LIFECYCLE %s", lifecycle)
				if arm == "direct" && (observation.Status != tc.status || observation.Handler != tc.handler || observation.Backend != tc.backend) {
					t.Errorf("direct baseline changed: %s", data)
				}
				benignCase := tc.name == "fixed-json" || tc.name == "chunked-json"
				if benignCase && (observation.Status != 200 || observation.Backend != 1) {
					t.Errorf("benign forwarding failed: %s", data)
				}
				if tc.backend == 0 && (observation.Backend != 0 || (observation.Status >= 200 && observation.Status < 300)) {
					t.Errorf("rejected input forwarded/succeeded: %s", data)
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
				if observation.Handler > 0 && (tc.name == "json-script" || tc.name == "json-script-halfclose" || tc.name == "form-sql") {
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
				if tc.stall && observation.Handler > 0 && observation.SourceCloseError != "timeout" {
					t.Fatalf("stalled source Close classification: %s", data)
				}
				if !observation.ConnectionClosed || !observation.ServerJoined || !observation.ListenerAbsent {
					t.Fatalf("cleanup gates: %s", data)
				}
			})
		}
	}
}
