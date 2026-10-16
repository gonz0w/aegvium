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
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

type requestWireEffect struct {
	Authority, Body, Path string
	Trailers              int
	Clean                 bool
}
type requestWireCase struct {
	name, request, body string
	status, effects     int
}
type requestWireRow struct {
	Mode           string `json:"mode"`
	Case           string `json:"case"`
	InputSHA       string `json:"input_sha256"`
	Sent           int    `json:"sent"`
	TLS            bool   `json:"verified_tls"`
	Status         int    `json:"status"`
	Responses      int    `json:"responses"`
	Closed         bool   `json:"server_closed"`
	AdditionalByte bool   `json:"additional_byte"`
	Backend        int    `json:"backend"`
	Authority      string `json:"authority"`
	Path           string `json:"path"`
	BodySHA        string `json:"body_sha256"`
	Trailers       int    `json:"trailers"`
	Clean          bool   `json:"headers_clean"`
}

func requestWireCases() []requestWireCase {
	benign := `{"payload":"ordinary"}`
	attack := `{"payload":"<script>alert(1)</script>"}`
	headers := "Host: app.test\r\nUser-Agent: Aegvium owned lab\r\nAccept: */*\r\nConnection: keep-alive\r\nForwarded: for=192.0.2.80\r\nX-Forwarded-For: 192.0.2.81\r\nProxy-Authorization: synthetic\r\n"
	post := "POST /wire HTTP/1.1\r\n" + headers + "Content-Type: application/json\r\n"
	get := "GET /wire HTTP/1.1\r\n" + headers + "\r\n"
	fixed := "Content-Length: " + fmt.Sprint(len(benign)) + "\r\n"
	chunk := func(body string) string { return fmt.Sprintf("%x\r\n%s\r\n0\r\n", len(body), body) }
	chunked := "Transfer-Encoding: chunked\r\n"
	normal := post + fixed + "\r\n" + benign
	hostile := post + "Content-Length: " + fmt.Sprint(len(attack)) + "\r\n\r\n" + attack
	return []requestWireCase{
		{"get", get, "", 200, 1},
		{"json", normal, benign, 200, 1},
		{"chunked-json", post + chunked + "\r\n" + chunk(benign) + "\r\n", benign, 200, 1},
		{"chunked-attack", post + chunked + "\r\n" + chunk(attack) + "\r\n", "", 403, 0},
		{"equal-lengths", post + fixed + fixed + "\r\n" + benign, benign, 200, 1},
		{"conflicting-lengths", post + fixed + "Content-Length: 1\r\n\r\n" + benign, "", 400, 0},
		{"cl-te", post + "Content-Length: 1\r\n" + chunked + "\r\n" + chunk(benign) + "\r\n", benign, 200, 1},
		{"te-cl", post + chunked + "Content-Length: 1\r\n\r\n" + chunk(benign) + "\r\n", benign, 200, 1},
		{"duplicate-te", post + chunked + chunked + "\r\n" + chunk(benign) + "\r\n", "", 501, 0},
		{"unsupported-te", post + "Transfer-Encoding: gzip\r\n\r\n" + benign, "", 501, 0},
		{"bad-chunk", post + chunked + "\r\nXX\r\n" + benign + "\r\n0\r\n\r\n", "", 500, 0},
		{"truncated-length", post + "Content-Length: 100\r\n\r\n" + benign, "", 500, 0},
		{"truncated-chunk", post + chunked + "\r\n64\r\n" + benign, "", 500, 0},
		{"declared-trailer", post + chunked + "Trailer: X-Extra\r\n\r\n" + chunk(benign) + "X-Extra: synthetic\r\n\r\n", "", 400, 0},
		{"undeclared-trailer", post + chunked + "\r\n" + chunk(benign) + "X-Extra: synthetic\r\n\r\n", "", 400, 0},
		{"forwarded-trailer", post + chunked + "Trailer: Forwarded\r\n\r\n" + chunk(benign) + "Forwarded: for=192.0.2.99\r\n\r\n", "", 400, 0},
		{"authorization-trailer", post + chunked + "\r\n" + chunk(benign) + "Authorization: synthetic\r\n\r\n", "", 400, 0},
		{"empty-trailer", post + chunked + "Trailer: X-Extra\r\n\r\n" + chunk(benign) + "\r\n", "", 400, 0},
		{"invalid-trailer", post + chunked + "Trailer: Content-Length\r\n\r\n" + chunk(benign) + "\r\n", "", 400, 0},
		{"chunked-over", post + chunked + "\r\n" + chunk(strings.Repeat("x", LabBodyLimit+1)) + "\r\n", "", 413, 0},
		{"get-body", "GET /wire HTTP/1.1\r\n" + headers + fixed + "\r\n" + benign, "", 400, 0},
		{"pipeline-benign", normal + get, benign, 200, 1},
		{"pipeline-attack", normal + hostile, benign, 200, 1},
		{"denied-pipeline", hostile + get, "", 403, 0},
		{"bad-pipeline", post + fixed + "Content-Length: 1\r\n\r\n" + benign + get, "", 400, 0},
		{"recovery", get, "", 200, 1},
	}
}

func TestLabRequestWire(t *testing.T) { runTLSPathOptions(t, false, true) }
func TestLabRequestWireNative(t *testing.T) {
	if runtime.GOOS != "openbsd" || os.Getenv("AEGVIUM_LAB_REQUEST_WIRE") != "owned-guest" {
		t.Skip("owned OpenBSD wire profile required")
	}
	if os.Getuid() != 32767 || os.Geteuid() != 32767 {
		t.Fatal("wire fixture UID")
	}
	runTLSPathOptions(t, true, true)
}

func runRequestWire(t *testing.T, guest bool, dial func(bool) (net.Conn, error), config func(string) *tls.Config, observe func() []requestWireEffect) {
	t.Helper()
	modes := []string{"direct"}
	if guest {
		modes = append(modes, "relayd")
	}
	for _, mode := range modes {
		for _, tc := range requestWireCases() {
			t.Run("wire-"+mode+"-"+tc.name, func(t *testing.T) {
				before := len(observe())
				c, err := dial(mode == "direct")
				if err != nil {
					t.Fatal(err)
				}
				defer c.Close()
				// The server read budget is 2s. An external deadline is never safe rejection.
				if err = c.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
					t.Fatal(err)
				}
				secure := tls.Client(c, config("app.test"))
				if err = secure.Handshake(); err != nil {
					t.Fatal(err)
				}
				state := secure.ConnectionState()
				digest := sha256.Sum256([]byte(tc.request))
				row := requestWireRow{Mode: mode, Case: tc.name, InputSHA: hex.EncodeToString(digest[:]), TLS: len(state.VerifiedChains) > 0 && state.NegotiatedProtocol == "http/1.1", Clean: true}
				row.Sent, err = io.WriteString(secure, tc.request)
				if err != nil || row.Sent != len(tc.request) {
					t.Fatal("wire write", err)
				}
				reader := bufio.NewReader(secure)
				response, err := http.ReadResponse(reader, &http.Request{Method: strings.Fields(tc.request)[0]})
				if err != nil {
					t.Fatal("wire response", err)
				}
				row.Status = response.StatusCode
				row.Responses = 1
				_, err = io.ReadAll(io.LimitReader(response.Body, 8193))
				response.Body.Close()
				if err != nil {
					t.Fatal("wire response body", err)
				}
				// Read a raw byte until the server closes; do not close the
				// client first or assume missing second effects merely from response one.
				_, err = reader.ReadByte()
				if err == nil {
					row.AdditionalByte = true // Any trailing byte violates the one-response contract.
				} else if errors.Is(err, io.EOF) {
					row.Closed = true
				}
				if !response.Close {
					t.Error("response did not declare close")
				}
				after := observe()
				row.Backend = len(after) - before
				if row.Backend == 1 {
					effect := after[before]
					body := sha256.Sum256([]byte(effect.Body))
					row.Authority, row.Path, row.BodySHA, row.Trailers, row.Clean = effect.Authority, effect.Path, hex.EncodeToString(body[:]), effect.Trailers, effect.Clean
				}
				raw, _ := json.Marshal(row)
				t.Log("REQUEST-WIRE " + string(raw))
				if row.Status != tc.status || row.Backend != tc.effects || !row.TLS || !row.Closed || row.Responses != 1 || row.AdditionalByte || !row.Clean || row.Trailers != 0 {
					t.Fatalf("wire result %+v wanted %d/%d; terminal %v", row, tc.status, tc.effects, err)
				}
				if row.Backend == 1 {
					body := sha256.Sum256([]byte(tc.body))
					if row.Authority != "app.test" || row.Path != "/wire" || row.BodySHA != hex.EncodeToString(body[:]) {
						t.Fatal("wire backend bytes/authority/path")
					}
				}
			})
		}
	}
	t.Logf("REQUEST-WIRE-FINAL modes=%d cases=%d client_deadline_accepted=false", len(modes), len(requestWireCases())*len(modes))
}
