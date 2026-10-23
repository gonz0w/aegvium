// SPDX-License-Identifier: BSD-3-Clause
package requestctx

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Fixed failure classes carry no request text, peer proof or serving authority.
var (
	ErrDataInput       = errors.New("invalid data request")
	ErrDataHeaderLimit = errors.New("data request header limit")
	ErrDataBodyLimit   = errors.New("data request body limit")
	ErrDataAuthority   = errors.New("data request authority mismatch")
	ErrDataForbidden   = errors.New("data request role forbidden")
	ErrDataUnavailable = errors.New("data request generation unavailable")
)

// Preserve raw field occurrences BEFORE the standard HTTP parser can normalize
// them. This is the internal hop only, not original-public framing proof.
func rawDataFieldsStatus(header []byte, cap int) ([]Field, error) {
	if len(header) > cap {
		return nil, ErrDataHeaderLimit
	}
	if !bytes.HasSuffix(header, []byte("\r\n\r\n")) {
		return nil, ErrDataInput
	}
	lines := bytes.Split(header, []byte("\r\n"))
	if len(lines) < 3 || len(lines[0]) == 0 {
		return nil, ErrDataInput
	}
	fields := make([]Field, 0, MaxFields)
	for _, line := range lines[:len(lines)-2] {
		if bytes.ContainsAny(line, "\r\n") {
			return nil, ErrDataInput
		}
	}
	for _, line := range lines[1 : len(lines)-2] {
		name, value, found := strings.Cut(string(line), ": ")
		if len(fields) == MaxFields || len(name) > 128 || len(value) > 4096 {
			return nil, ErrDataHeaderLimit
		}
		if !found || !fieldName(name) || !fieldValue(value) {
			return nil, ErrDataInput
		}
		fields = append(fields, Field{name, value})
	}
	return fields, nil
}
func rawDataFields(header []byte, cap int) ([]Field, bool) {
	fields, err := rawDataFieldsStatus(header, cap)
	return fields, err == nil
}
func parseDataRequestHeader(header []byte) (Request, int, bool) {
	r, n, err := parseDataRequestHeaderStatus(header)
	return r, n, err == nil
}
func parseDataRequestHeaderStatus(header []byte) (Request, int, error) {
	fields, err := rawDataFieldsStatus(header, 5120)
	if err != nil {
		return Request{}, 0, err
	}
	seen := map[string]bool{}
	publicBytes := bytes.Index(header, []byte("\r\n")) + 4
	contextBytes := 0
	for _, f := range fields {
		n := strings.ToLower(f.Name)
		size := len(f.Name) + 2 + len(f.Value) + 2
		if strings.HasPrefix(n, "aegvium-") {
			contextBytes += size
		} else {
			publicBytes += size
		}
		if publicBytes > 4096 || contextBytes > 1024 || publicBytes+contextBytes > 5120 {
			return Request{}, 0, ErrDataHeaderLimit
		}
		switch n {
		case "host", "content-length", "connection", "content-type":
			if seen[n] {
				return Request{}, 0, ErrDataInput
			}
			seen[n] = true
		case "transfer-encoding", "trailer", "content-encoding", "te", "expect", "upgrade", "proxy-connection", "keep-alive":
			return Request{}, 0, ErrDataInput
		}
		if n == "content-length" {
			v, e := strconv.ParseUint(f.Value, 10, 64)
			if e != nil || strconv.FormatUint(v, 10) != f.Value {
				return Request{}, 0, ErrDataInput
			}
			if v > 4096 {
				return Request{}, 0, ErrDataBodyLimit
			}
		}
	}
	// Standard parser validates HTTP syntax; only preserved raw fields are
	// projected/inspected/forwarded. Its memory-only body owns no endpoint.
	r, e := http.ReadRequest(bufio.NewReader(bytes.NewReader(header)))
	if e != nil {
		return Request{}, 0, ErrDataInput
	}
	_ = r.Body.Close()
	line := r.Method + " " + r.RequestURI + " " + r.Proto + "\r\n"
	if !bytes.HasPrefix(header, []byte(line)) || r.Proto != "HTTP/1.1" || !seen["host"] || len(r.TransferEncoding) != 0 || len(r.Trailer) != 0 || r.ContentLength < 0 || r.ContentLength > 4096 {
		return Request{}, 0, ErrDataInput
	}
	return Request{Protocol: r.Proto, Method: r.Method, Target: r.RequestURI, Fields: fields}, int(r.ContentLength), nil
}
func dataProjectionFailure(err error) error {
	switch err {
	case ErrAuthority:
		return ErrDataAuthority
	case ErrPeer:
		return ErrDataForbidden
	case ErrGeneration, ErrRetired, ErrCapacity:
		return ErrDataUnavailable
	default:
		return ErrDataInput
	}
}

func publicDataRequest(r Record) []byte {
	var out bytes.Buffer
	out.WriteString(r.Method + " " + r.Target + " " + r.Protocol + "\r\n")
	for _, f := range r.Fields {
		out.WriteString(f.Name + ": " + f.Value + "\r\n")
	}
	out.WriteString("\r\n")
	out.Write(r.Body)
	return out.Bytes()
}

// Fixed-length source response profile. Unsupported backend representations
// cause a bounded502 after a possibly effected attempt, never a retry/fallback.
func parseDataResponseHeader(header []byte, method string) (int, bool) {
	fields, ok := rawDataFields(header, 4096)
	if !ok {
		return 0, false
	}
	length := -1
	connection := false
	for _, f := range fields {
		n := strings.ToLower(f.Name)
		if strings.HasPrefix(n, "aegvium-") {
			return 0, false
		}
		switch n {
		case "content-length":
			v, e := strconv.ParseUint(f.Value, 10, 16)
			if length != -1 || e != nil || v > 4096 || strconv.FormatUint(v, 10) != f.Value {
				return 0, false
			}
			length = int(v)
		case "transfer-encoding", "trailer", "upgrade", "proxy-connection", "keep-alive":
			return 0, false
		case "connection":
			if connection || !strings.EqualFold(f.Value, "close") {
				return 0, false
			}
			connection = true
		}
	}
	r, e := http.ReadResponse(bufio.NewReader(bytes.NewReader(header)), &http.Request{Method: method})
	if e != nil {
		return 0, false
	}
	_ = r.Body.Close()
	if r.Proto != "HTTP/1.1" || r.StatusCode < 200 || r.StatusCode > 599 || len(r.TransferEncoding) != 0 || len(r.Trailer) != 0 || !bytes.HasPrefix(header, []byte(r.Proto+" "+r.Status+"\r\n")) {
		return 0, false
	}
	if method == "HEAD" || r.StatusCode == 204 || r.StatusCode == 304 {
		if r.StatusCode == 204 && length > 0 {
			return 0, false
		}
		return 0, true
	}
	return length, length >= 0
}

func readDataExact(ctx context.Context, until time.Time, src io.Reader, out []byte) bool {
	for at, empty := 0, 0; at < len(out); {
		if ctx.Err() != nil || !time.Now().Before(until) {
			return false
		}
		n, e := src.Read(out[at:])
		if n < 0 || n > len(out)-at {
			return false
		}
		at += n
		if e != nil {
			return e == io.EOF && at == len(out) && ctx.Err() == nil && time.Now().Before(until)
		}
		if n == 0 {
			empty++
			if empty == 100 {
				return false
			}
		} else {
			empty = 0
		}
	}
	return ctx.Err() == nil && time.Now().Before(until)
}

func readDataHeader(ctx context.Context, until time.Time, src io.Reader, cap int) ([]byte, bool) {
	out := make([]byte, 0, cap)
	var one [1]byte
	for len(out) < cap {
		if !readDataExact(ctx, until, src, one[:]) {
			return nil, false
		}
		out = append(out, one[0])
		if bytes.HasSuffix(out, []byte("\r\n\r\n")) {
			return out, true
		}
	}
	return out, false
}

func dataErrorResponse(code int) []byte {
	text := map[int]string{400: "Bad Request", 403: "Forbidden", 421: "Misdirected Request", 431: "Request Header Fields Too Large", 413: "Content Too Large", 503: "Service Unavailable", 502: "Bad Gateway", 504: "Gateway Timeout"}[code]
	if text == "" {
		code = 503
		text = "Service Unavailable"
	}
	return []byte("HTTP/1.1 " + strconv.Itoa(code) + " " + text + "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
}
