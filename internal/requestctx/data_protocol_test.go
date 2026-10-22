// SPDX-License-Identifier: BSD-3-Clause
package requestctx

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

func dataWireLiteral(t *testing.T) ([]byte, []byte) {
	t.Helper()
	b, e := os.ReadFile("testdata/connection_facts.json")
	if e != nil {
		t.Fatal(e)
	}
	var f struct {
		Canonical struct {
			Internal    string `json:"internal_request_ascii"`
			Application string `json:"expected_application_request_ascii"`
		} `json:"canonical"`
	}
	if json.Unmarshal(b, &f) != nil {
		t.Fatal("public literal")
	}
	return []byte(f.Canonical.Internal), []byte(f.Canonical.Application)
}

func TestDataProtocolSameRequestFactsAndBackendBytes(t *testing.T) {
	wire, want := dataWireLiteral(t)
	s, _, _ := pair2Fixture(t, "joint")
	input, n, ok := parseDataRequestHeader(wire)
	if !ok || n != 0 {
		t.Fatal("joint literal did not parse")
	}
	row, e := s.context.project(Peer{identity: "front-a.internal.test"}, input)
	if e != nil || row.PublicPort != 443 || row.Local.String() != "10.0.0.4:8443" || row.Remote.String() != "198.51.100.7:49152" {
		t.Fatal("same-request public facts lost")
	}
	if !bytes.Equal(publicDataRequest(row), want) {
		t.Fatal("reserved stripping or public request bytes changed")
	}
	// A second frame remains unread; the serving job has exactly one exchange.
	stream := bytes.NewReader(append(append([]byte(nil), wire...), wire...))
	head, ok := readDataHeader(context.Background(), time.Now().Add(time.Hour), stream, 5120)
	if !ok || !bytes.Equal(head, wire) || stream.Len() != len(wire) {
		t.Fatal("reader consumed more than one frame")
	}
}

func TestDataProtocolVectSourceCorrelationAndSharedContract(t *testing.T) {
	wire, want := dataWireLiteral(t)
	s, _, _ := pair2Fixture(t, "joint")
	// Published Vect source e289598 uses G + '-' + positive int64, maximum52
	// bytes. This is correlation only; other conforming frontend IDs remain valid.
	id := "0123456789abcdef0123456789abcdef-9223372036854775807"
	if len(id) != 52 {
		t.Fatal("joint producer bound")
	}
	wire = bytes.Replace(wire, []byte("Aegvium-Request: req_7\r\n"), []byte("Aegvium-Request: "+id+"\r\n"), 1)
	in, n, ok := parseDataRequestHeader(wire)
	if !ok || n != 0 {
		t.Fatal("published producer fields do not fit receiver")
	}
	r, err := s.context.project(Peer{identity: "front-a.internal.test"}, in)
	if err != nil || r.RequestID != id || !bytes.Equal(publicDataRequest(r), want) {
		t.Fatal("producer/receiver context binding mismatch")
	}
}

func TestDataProtocolRejectsOriginalInternalFramingBeforeNormalization(t *testing.T) {
	wire, _ := dataWireLiteral(t)
	for _, extra := range []string{
		"Content-Length: 0\r\ncontent-length: 0\r\n", "Content-Length: 0\r\nTransfer-Encoding: chunked\r\n",
		"Content-Length: 00\r\n", "Content-Length: 4097\r\n", "Content-Length: +0\r\n", "Host: app.example.test\r\n",
		"TE: trailers\r\n", "Content-Encoding: gzip\r\n", "\tFolded: x\r\n", "Bad Name: x\r\n", "X-A: x\nY: z\r\n",
	} {
		bad := bytes.Replace(wire, []byte("\r\n\r\n"), []byte("\r\n"+extra+"\r\n"), 1)
		if _, _, ok := parseDataRequestHeader(bad); ok {
			t.Fatal("raw internal framing accepted")
		}
	}
	for _, bad := range [][]byte{wire[:len(wire)-1], append(bytes.Repeat([]byte("x"), 5121), []byte("\r\n\r\n")...), bytes.Replace(wire, []byte("HTTP/1.1"), []byte("HTTP/1.0"), 1)} {
		if _, _, ok := parseDataRequestHeader(bad); ok {
			t.Fatal("invalid/overbound header accepted")
		}
	}
	for _, alias := range []string{"Aegvium-Client: 198.51.100.7\r\n", "aegvium-connection: 198.51.100.7:49152/10.0.0.4:8443\r\n"} {
		bad := bytes.Replace(wire, []byte("\r\n\r\n"), []byte("\r\n"+alias+"\r\n"), 1)
		in, _, ok := parseDataRequestHeader(bad)
		if !ok {
			continue
		}
		s, _, _ := pair2Fixture(t, "joint")
		if _, e := s.context.project(Peer{identity: "front-a.internal.test"}, in); e == nil {
			t.Fatal("reserved alias admitted")
		}
	}
}

func TestDataProtocolBoundedFixedResponse(t *testing.T) {
	for _, tc := range []struct {
		method, header string
		length         int
		ok             bool
	}{
		{"GET", "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n", 2, true},
		{"HEAD", "HTTP/1.1 200 OK\r\nContent-Length: 4096\r\n\r\n", 0, true},
		{"GET", "HTTP/1.1 204 No Content\r\n\r\n", 0, true},
		{"GET", "HTTP/1.1 304 Not Modified\r\n\r\n", 0, true},
		{"GET", "HTTP/1.1 200 OK\r\nContent-Length: 4096\r\n\r\n", 4096, true},
		{"GET", "HTTP/1.1 200 OK\r\nContent-Length: 4097\r\n\r\n", 0, false},
		{"GET", "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n", 0, false},
		{"GET", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n", 0, false},
		{"GET", "HTTP/1.1 101 Switching Protocols\r\nContent-Length: 0\r\n\r\n", 0, false},
		{"GET", "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nAegvium-Connection: x\r\n\r\n", 0, false},
		{"GET", "HTTP/1.1 204 No Content\r\nContent-Length: 2\r\n\r\n", 0, false},
	} {
		n, ok := parseDataResponseHeader([]byte(tc.header), tc.method)
		if ok != tc.ok || ok && n != tc.length {
			t.Fatal("response body/representation bound mismatch")
		}
	}
}

func TestDataProtocolReadBoundsAndTerminalEOF(t *testing.T) {
	until := time.Now().Add(time.Hour)
	ctx := context.Background()
	var dst [2]byte
	if !readDataExact(ctx, until, bytes.NewReader([]byte("ab")), dst[:]) {
		t.Fatal("fixed body refused")
	}
	if !readDataExact(ctx, until, pairReadFunc(func(p []byte) (int, error) { copy(p, "ab"); return 2, io.EOF }), dst[:]) {
		t.Fatal("exact final bytes+EOF refused")
	}
	for _, n := range []int{-1, 3} {
		if readDataExact(ctx, until, pairReadFunc(func([]byte) (int, error) { return n, nil }), dst[:]) {
			t.Fatal("invalid source count accepted")
		}
	}
	if readDataExact(ctx, until, bytes.NewReader([]byte("a")), dst[:]) {
		t.Fatal("truncated body accepted")
	}
	calls := 0
	if readDataExact(ctx, until, pairReadFunc(func([]byte) (int, error) { calls++; return 0, nil }), dst[:]) || calls != 100 {
		t.Fatal("unbounded empty reads")
	}
	for _, n := range []int{5119, 5120, 5121} {
		value := strings.Repeat("a", n-4) + "\r\n\r\n"
		_, ok := readDataHeader(ctx, until, strings.NewReader(value), 5120)
		if ok != (n <= 5120) {
			t.Fatal("header cap boundary")
		}
	}
	for _, code := range []int{400, 403, 421, 431, 413, 503, 502, 504, 0} {
		if len(dataErrorResponse(code)) > 128 || !bytes.HasSuffix(dataErrorResponse(code), []byte("Content-Length: 0\r\nConnection: close\r\n\r\n")) {
			t.Fatal("unbounded failure response")
		}
	}
}

func TestDataProtocolFixedFailureClasses(t *testing.T) {
	wire, _ := dataWireLiteral(t)
	for _, tc := range []struct {
		extra string
		want  error
	}{
		{"Content-Length: 4097\r\n", ErrDataBodyLimit},
		{"Content-Length: 00\r\n", ErrDataInput},
		{strings.Repeat("X-A: z\r\n", 65), ErrDataHeaderLimit},
		{"X-A: " + strings.Repeat("x", 4096) + "\r\n", ErrDataHeaderLimit},
		{"Aegvium-Unrecognized: " + strings.Repeat("x", 1024) + "\r\n", ErrDataHeaderLimit},
	} {
		bad := bytes.Replace(wire, []byte("\r\n\r\n"), []byte("\r\n"+tc.extra+"\r\n"), 1)
		if _, _, err := parseDataRequestHeaderStatus(bad); err != tc.want {
			t.Fatal("fixed limit classification lost")
		}
	}
	for _, tc := range []struct{ input, want error }{
		{ErrAuthority, ErrDataAuthority}, {ErrPeer, ErrDataForbidden},
		{ErrGeneration, ErrDataUnavailable}, {ErrRetired, ErrDataUnavailable},
		{ErrInput, ErrDataInput},
	} {
		if dataProjectionFailure(tc.input) != tc.want {
			t.Fatal("fixed projection classification lost")
		}
	}
}
