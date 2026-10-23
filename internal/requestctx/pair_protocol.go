// SPDX-License-Identifier: BSD-3-Clause
package requestctx

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net/http"
	"net/textproto"
	"strings"
	"time"
)

func readPairExact(ctx context.Context, until time.Time, src io.Reader, out []byte) bool {
	at, empty := 0, 0
	for at < len(out) {
		if ctx.Err() != nil || !time.Now().Before(until) {
			return false
		}
		n, err := src.Read(out[at:])
		if n < 0 || n > len(out)-at || err != nil {
			return false
		}
		if n == 0 {
			empty++
			if empty == 100 {
				return false
			}
			continue
		}
		empty = 0
		at += n
	}
	return ctx.Err() == nil && time.Now().Before(until)
}
func readPairHeader(ctx context.Context, until time.Time, src io.Reader) ([]byte, bool) {
	header := make([]byte, 0, 4096)
	var b [1]byte
	for len(header) < 4096 {
		if !readPairExact(ctx, until, src, b[:]) {
			return nil, false
		}
		header = append(header, b[0])
		if bytes.HasSuffix(header, []byte("\r\n\r\n")) {
			return header, true
		}
	}
	return nil, false
}

// Preserved bounded control headers precede standard HTTP parsing. This is NOT
// original-application framing admission; no application payload is processed.
func pairHTTPStatus(s *pairedSnapshot, header, body []byte) int {
	if s == nil || len(header) > 4096 || !bytes.HasSuffix(header, []byte("\r\n\r\n")) || len(body) != 104 {
		return 400
	}
	lines := bytes.Split(header, []byte("\r\n"))
	for i, line := range lines {
		if bytes.ContainsAny(line, "\r\n") || (i > 0 && len(line) > 0 && (line[0] == ' ' || line[0] == '\t')) {
			return 400
		}
	}
	tp := textproto.NewReader(bufio.NewReader(bytes.NewReader(header)))
	if _, err := tp.ReadLine(); err != nil {
		return 400
	}
	h, err := tp.ReadMIMEHeader()
	if err != nil || len(h.Values("Host")) != 1 || len(h.Values("Content-Length")) != 1 || len(h.Values("Connection")) != 1 {
		return 400
	}
	if h.Get("Content-Length") != "104" || !strings.EqualFold(h.Get("Connection"), "close") || !authority(h.Get("Host"), s.serverName, s.port) {
		return 400
	}
	for _, name := range []string{"Transfer-Encoding", "Content-Encoding", "Trailer", "TE", "Expect", "Upgrade", "Proxy-Connection", "Keep-Alive"} {
		if len(h.Values(name)) != 0 {
			return 400
		}
	}
	data := make([]byte, 0, len(header)+104)
	data = append(data, header...)
	data = append(data, body...)
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(data)))
	if err != nil {
		return 400
	}
	payload, readErr := io.ReadAll(io.LimitReader(req.Body, 105))
	closeErr := req.Body.Close() // Memory-only body; never wraps the TLS endpoint.
	if readErr != nil || closeErr != nil || len(payload) != 104 || req.Method != "POST" || req.Proto != "HTTP/1.1" || req.RequestURI != "/_aegvium/m2-h1-1/pair" || req.ContentLength != 104 || len(req.TransferEncoding) != 0 || len(req.Trailer) != 0 || !req.Close {
		return 400
	}
	if !bytes.Equal(payload[:8], []byte("AGCHECK1")) || !hex(string(payload[8:40]), 32) || !bytes.Equal(payload[72:], s.tuple[72:]) {
		return 400
	}
	if !bytes.Equal(payload, s.tuple[:]) {
		return 409
	}
	return 200 // Prepared local bytes ONLY, not authenticated/Ready/allow proof.
}
func pairResponse(s *pairedSnapshot, code int) []byte {
	if code == 200 && s != nil {
		out := []byte("HTTP/1.1 200 OK\r\nContent-Length: 104\r\nConnection: close\r\n\r\n")
		return append(out, s.tuple[:]...)
	}
	line := "503 Service Unavailable"
	if code == 400 {
		line = "400 Bad Request"
	}
	if code == 409 {
		line = "409 Conflict"
	}
	return []byte("HTTP/1.1 " + line + "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
}
func writePairExact(ctx context.Context, until time.Time, dst io.Writer, p []byte) bool {
	for len(p) > 0 {
		if ctx.Err() != nil || !time.Now().Before(until) {
			return false
		}
		n, err := dst.Write(p)
		if n <= 0 || n > len(p) || err != nil {
			return false
		}
		p = p[n:]
	}
	return ctx.Err() == nil && time.Now().Before(until)
}
