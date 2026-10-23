//go:build aegvium_frontend_source

// Adapted from private Vectivium e28959892903225887d855677c307712a59ce071; see LICENSE.Vectivium.
// No public relicensing is made.
package frontendclient

// These controls exercise data/framing and private ownership policy only.
// They NEVER call NewSource, MatchPreparedSource, TLS/X509 constructors or dial.
// No positive authenticated pairing, actual endpoint or frontend owner is mocked.
import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

func fixture(t *testing.T) ([]byte, []byte) {
	t.Helper()
	raw, err := os.ReadFile("../requestctx/testdata/pair_prepared.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Descriptor string `json:"descriptor_hex"`
		Prepared   string `json:"prepared_hex"`
	}
	if json.Unmarshal(raw, &f) != nil {
		t.Fatal("fixture")
	}
	d, e1 := hex.DecodeString(f.Descriptor)
	q, e2 := hex.DecodeString(f.Prepared)
	if e1 != nil || e2 != nil || len(d) != 313 || len(q) != 104 {
		t.Fatal("fixture lengths")
	}
	return d, q
}
func memoryState() *sourceState {
	now := time.Now()
	return &sourceState{ctx: context.Background(), started: now, total: now.Add(time.Hour)}
}
func TestControlDataFrozenRequestAndDetachedTuple(t *testing.T) {
	d, q := fixture(t)
	p, err := parsePair(d, "front-a.internal.test")
	if err != nil || !bytes.Equal(p.tuple[:], q) {
		t.Fatal("independent tuple")
	}
	header := "POST /_aegvium/m2-h1-1/pair HTTP/1.1\r\nHost: inspect.internal.test:8443\r\nContent-Length: 104\r\nConnection: close\r\n\r\n"
	want := append([]byte(header), q...)
	if !bytes.Equal(controlRequest(p), want) {
		t.Fatal("fixed control request")
	}
	for i := range d {
		d[i] = 0
	}
	if !bytes.Equal(controlRequest(p), want) {
		t.Fatal("caller mutation")
	}
	// Construct only historical data in this pure control, never a TLS result.
	var zero PreparedMatch
	if _, ok := zero.Tuple(); ok {
		t.Fatal("zero result")
	}
	m := PreparedMatch{tuple: p.tuple, complete: true}
	copy, ok := m.Tuple()
	copy[0] = 0
	second, _ := m.Tuple()
	if !ok || second != p.tuple {
		t.Fatal("result data alias")
	}
}
func TestControlDataRejectsWrongProfilesRolesAndBoundaries(t *testing.T) {
	d, _ := fixture(t)
	mutations := [][]byte{d[:312], append(bytes.Clone(d), 0), make([]byte, 8193)}
	for _, change := range []struct {
		offset int
		value  byte
	}{{0, 'X'}, {46, '2'}, {291, 1}, {311, 5}} {
		v := bytes.Clone(d)
		v[change.offset] = change.value
		mutations = append(mutations, v)
	}
	for i, v := range mutations {
		if _, err := parsePair(v, "front-a.internal.test"); err == nil {
			t.Fatalf("accepted mutation%d", i)
		}
	}
	for _, role := range []string{"", "Front-a.internal.test", "outside.internal.test", "inspect.internal.test", strings.Repeat("x", 254)} {
		if _, err := parsePair(d, role); err == nil {
			t.Fatal("unexpected role")
		}
	}
	if _, err := parsePair(d, "front-b.internal.test"); err != nil {
		t.Fatal("second explicit permitted role")
	}
}
func TestControlDataEveryRouteMustShareEndpointAndRoleAnchors(t *testing.T) {
	d, _ := fixture(t)
	first := bytes.Clone(d[48 : len(d)-22])
	second := bytes.Clone(first)
	second[11] = 'z' // app_primarz sorts after app_primary.
	second[14] = 'b' // bpp.example.test is a distinct application authority.
	build := func(route []byte) []byte {
		out := bytes.Clone(d[:48])
		out[47] = 2
		out = append(out, first...)
		out = append(out, route...)
		return append(out, d[len(d)-22:]...)
	}
	if _, err := parsePair(build(second), "front-a.internal.test"); err != nil {
		t.Fatal("common two-route source profile")
	}
	for index, offset := range []int{len(second) - 1, len(second) - 64,
		bytes.Index(second, []byte("192.0.2.10")) + 9,
		bytes.Index(second, []byte("inspect.internal.test")),
		bytes.Index(second, []byte("front-a.internal.test")) + 6} {
		changed := bytes.Clone(second)
		changed[offset] ^= 1
		if index == 4 {
			changed[offset] = '0' // Canonical front-0 sorts before front-b.
		}
		encoded := build(changed)
		if _, err := parseDescriptor(encoded); err != nil {
			t.Fatal("negative must remain a structurally valid descriptor")
		}
		if _, err := parsePair(encoded, "front-a.internal.test"); err == nil {
			t.Fatal("cross-route endpoint/anchor/role mismatch")
		}
	}
}

func TestControlDataResponseVectorsAreNotAuthentication(t *testing.T) {
	d, q := fixture(t)
	p, err := parsePair(d, "front-a.internal.test")
	if err != nil {
		t.Fatal(err)
	}
	// Independent literal from the Aeg receiver, never the candidate constant.
	const expectedHeader = "HTTP/1.1 200 OK\r\nContent-Length: 104\r\nConnection: close\r\n\r\n"
	good := append([]byte(expectedHeader), q...)
	cases := []struct {
		name string
		data []byte
		want bool
	}{
		{"exact", good, true},
		{"400", []byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"), false},
		{"409", []byte("HTTP/1.1 409 Conflict\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"), false},
		{"503", []byte("HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"), false},
		{"extra body", append(bytes.Clone(good), 'x'), false},
		{"short body", good[:len(good)-1], false},
		{"duplicate length", append([]byte("HTTP/1.1 200 OK\r\nContent-Length: 104\r\nContent-Length: 104\r\nConnection: close\r\n\r\n"), q...), false},
		{"extra header", append([]byte("HTTP/1.1 200 OK\r\nContent-Length: 104\r\nConnection: close\r\nX-Other: x\r\n\r\n"), q...), false},
		{"encoding", append([]byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"), q...), false},
		{"oversize", []byte(strings.Repeat("x", 4097)), false},
	}
	for _, index := range []int{8, 40, 72, 103} {
		bad := bytes.Clone(good)
		bad[len(expectedHeader)+index] ^= 1
		cases = append(cases, struct {
			name string
			data []byte
			want bool
		}{"wrong tuple", bad, false})
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := memoryState()
			got := readPreparedResponse(s, bytes.NewReader(c.data), s.total, p)
			if got != c.want {
				t.Fatal("response mismatch")
			}
			if len(s.header) > 4096 || len(s.response) > 104 {
				t.Fatal("capture cap")
			}
		})
	}
	for _, size := range []int{1, 2, 17, 103} {
		s := memoryState()
		r := &fragmentReader{data: bytes.Clone(good), chunk: size}
		if !readPreparedResponse(s, r, s.total, p) {
			t.Fatal("finite fragmentation")
		}
	}
	for _, tc := range []struct {
		data []byte
		err  error
		want bool
	}{{good, io.EOF, true}, {good[:len(good)-1], io.EOF, false}, {good, io.ErrUnexpectedEOF, false}} {
		s := memoryState()
		if readPreparedResponse(s, &fragmentReader{data: bytes.Clone(tc.data), chunk: 104, finalErr: tc.err}, s.total, p) != tc.want {
			t.Fatal("final bytes and EOF/error")
		}
	}
	s := memoryState()
	if readPreparedResponse(s, &fragmentReader{data: good, chunk: 7, noEOF: true}, s.total, p) {
		t.Fatal("missing EOF")
	}
}

type fragmentReader struct {
	data     []byte
	chunk    int
	noEOF    bool
	finalErr error
	after    func()
}

func (r *fragmentReader) Read(p []byte) (int, error) {
	if r.after != nil {
		f := r.after
		r.after = nil
		f()
	}
	if len(r.data) == 0 {
		if r.noEOF {
			return 0, nil
		}
		return 0, io.EOF
	}
	n := len(p)
	if n > r.chunk {
		n = r.chunk
	}
	if n > len(r.data) {
		n = len(r.data)
	}
	copy(p, r.data[:n])
	r.data = r.data[n:]
	if len(r.data) == 0 && r.finalErr != nil {
		return n, r.finalErr
	}
	return n, nil
}

type countReader struct {
	n   int
	err error
}

func (r countReader) Read([]byte) (int, error) { return r.n, r.err }

type memoryWriter struct {
	buf     bytes.Buffer
	max     int
	fail    bool
	zero    bool
	invalid bool
	after   func()
}

func (w *memoryWriter) Write(p []byte) (int, error) {
	if w.after != nil {
		f := w.after
		w.after = nil
		f()
	}
	if w.invalid {
		return len(p) + 1, nil
	}
	if w.zero {
		return 0, nil
	}
	n := len(p)
	if n > w.max {
		n = w.max
	}
	w.buf.Write(p[:n])
	if w.fail {
		return n, io.ErrUnexpectedEOF
	}
	return n, nil
}
func TestControlDataPartialCountsErrorsAndOriginalClock(t *testing.T) {
	for _, r := range []io.Reader{countReader{-1, nil}, countReader{2, nil}, countReader{0, nil}, countReader{1, io.ErrUnexpectedEOF}} {
		s := memoryState()
		if complete, _ := readControlExact(s, r, s.total, make([]byte, 1)); complete {
			t.Fatal("invalid completion")
		}
	}
	s := memoryState()
	r := &fragmentReader{data: []byte{1}, chunk: 1, after: func() { s.mu.Lock(); s.total = time.Now(); s.mu.Unlock() }}
	if complete, _ := readControlExact(s, r, time.Now().Add(time.Hour), make([]byte, 1)); complete {
		t.Fatal("late read")
	}
	s = memoryState()
	w := &memoryWriter{max: 1}
	if !writeControl(s, w, s.total, []byte("abc")) || w.buf.String() != "abc" || s.written != 3 {
		t.Fatal("fragmented memory write")
	}
	for _, w := range []*memoryWriter{{max: 1, fail: true}, {zero: true}, {invalid: true}} {
		s := memoryState()
		if writeControl(s, w, s.total, []byte("abc")) {
			t.Fatal("invalid write")
		}
	}
	s = memoryState()
	w = &memoryWriter{max: 3, after: func() { s.mu.Lock(); s.total = time.Now(); s.mu.Unlock() }}
	if writeControl(s, w, time.Now().Add(time.Hour), []byte("abc")) {
		t.Fatal("late write")
	}
	s = memoryState()
	if complete, _ := readControlExact(s, bytes.NewReader([]byte{1}), time.Now(), make([]byte, 1)); complete {
		t.Fatal("stage equality")
	}
	oldTotal := s.total
	if s.until(oldTotal.Add(time.Hour)) != oldTotal {
		t.Fatal("renewed total")
	}
	cancelCtx, cancel := context.WithCancel(context.Background())
	s.ctx = cancelCtx
	copySource := Source{state: s}
	other := copySource
	other.RetireSource()
	cancel()
	if s.live() || !copySource.state.retired {
		t.Fatal("retirement alias")
	}
}
func TestControlDataNumericAndLexicalPreflightWithoutCrypto(t *testing.T) {
	d, _ := fixture(t)
	m := Materials{Descriptor: d, FrontendRole: "front-a.internal.test", CertificatePEM: []byte{1}, PrivateKeyPEM: []byte{1}, InspectorRootDER: []byte{1}, FrontendRootDER: []byte{1}}
	if !materialBounds(m) {
		t.Fatal("bounded opaque inputs")
	}
	bad := m
	bad.Descriptor = make([]byte, 8193)
	if materialBounds(bad) {
		t.Fatal("descriptor cap")
	}
	bad = m
	bad.CertificatePEM = make([]byte, 65537)
	if materialBounds(bad) {
		t.Fatal("chain cap")
	}
	bad = m
	bad.PrivateKeyPEM = make([]byte, 16385)
	if materialBounds(bad) {
		t.Fatal("key cap")
	}
	bad = m
	bad.InspectorRootDER = make([]byte, 16385)
	if materialBounds(bad) {
		t.Fatal("root cap")
	}
	bad = m
	bad.FrontendRootDER = nil
	if materialBounds(bad) {
		t.Fatal("empty root")
	}
	// A public one-byte PEM container is not a certificate or a key. No crypto
	// parser is invoked; positive means lexical structure only.
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1}})
	key := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1}})
	if !lexicalMaterial(cert, key) || !lexicalMaterial(bytes.Repeat(cert, 8), key) {
		t.Fatal("lexical blocks")
	}
	for _, c := range [][]byte{append([]byte("junk"), cert...), bytes.Repeat(cert, 9), append([]byte("-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----\n"), cert...)} {
		if lexicalMaterial(c, key) {
			t.Fatal("skipped/junk/oversize certificate")
		}
	}
	for _, k := range [][]byte{append(bytes.Clone(key), key...), append([]byte("junk"), key...), append(bytes.Clone(key), 'x')} {
		if lexicalMaterial(cert, k) {
			t.Fatal("ambiguous key")
		}
	}
}
func TestControlDataConflictingSANRolesWithoutParsing(t *testing.T) {
	d, _ := fixture(t)
	p, err := parsePair(d, "front-a.internal.test")
	if err != nil {
		t.Fatal(err)
	}
	client := &x509.Certificate{DNSNames: []string{"front-a.internal.test"}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	server := &x509.Certificate{DNSNames: []string{"inspect.internal.test"}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if !leafRole(client, p, false) || !leafRole(server, p, true) {
		t.Fatal("synthetic role shape")
	}
	client.DNSNames = append(client.DNSNames, "front-b.internal.test")
	if leafRole(client, p, false) {
		t.Fatal("ambiguous frontend role")
	}
	client.DNSNames = []string{"front-a.internal.test", "inspect.internal.test"}
	if leafRole(client, p, false) {
		t.Fatal("role collision")
	}
	server.DNSNames = append(server.DNSNames, "front-a.internal.test")
	if leafRole(server, p, true) {
		t.Fatal("server frontend collision")
	}
	server.DNSNames = []string{"*.internal.test"}
	if leafRole(server, p, true) {
		t.Fatal("wildcard role")
	}
}

type memoryConn struct {
	closes     int
	closeErr   error
	panicClose bool
}

func (c *memoryConn) Read([]byte) (int, error)    { return 0, io.EOF }
func (c *memoryConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *memoryConn) Close() error {
	c.closes++
	if c.panicClose {
		panic("synthetic close")
	}
	return c.closeErr
}
func (c *memoryConn) LocalAddr() net.Addr              { return nil }
func (c *memoryConn) RemoteAddr() net.Addr             { return nil }
func (c *memoryConn) SetDeadline(time.Time) error      { return nil }
func (c *memoryConn) SetReadDeadline(time.Time) error  { return nil }
func (c *memoryConn) SetWriteDeadline(time.Time) error { return nil }
func TestControlDataCloseOnceAndStickyUncertainty(t *testing.T) {
	for _, c := range []*memoryConn{{}, {closeErr: errors.New("synthetic")}, {panicClose: true}} {
		e := &ownedEndpoint{connection: c}
		want := c.closeErr == nil && !c.panicClose
		if e.finalize() != want || c.closes != 1 {
			t.Fatal("close outcome")
		}
		if e.Close() == nil || c.closes != 1 {
			t.Fatal("close retry")
		}
		if e.finalize() != want || c.closes != 1 {
			t.Fatal("historical close observation")
		}
	}
	c := &memoryConn{}
	e := &ownedEndpoint{connection: c}
	if !e.begin() {
		t.Fatal("synthetic active call")
	}
	if e.finalize() {
		t.Fatal("active close called clean")
	}
	e.end(true)
	if e.finalize() || c.closes != 1 || !e.uncertain {
		t.Fatal("uncertainty refunded")
	}
	if _, err := e.Write([]byte{1}); err == nil {
		t.Fatal("post-close operation")
	}
}

// Deterministic private clock policy, no replacement runtime clock or authority.
func TestControlDataExactClockBoundaries(t *testing.T) {
	start := time.Unix(100, 0)
	total := start.Add(2 * time.Second)
	parent := start.Add(time.Second)
	for _, delta := range []time.Duration{-1, 0, 1} {
		now := parent.Add(delta)
		if clockCurrent(now, start, total, parent) != (delta < 0) || beforeDeadline(now, parent) != (delta < 0) {
			t.Fatal("parent/stage exact boundary")
		}
		now = total.Add(delta)
		if clockCurrent(now, start, total, time.Time{}) != (delta < 0) {
			t.Fatal("total exact boundary")
		}
	}
	if clockCurrent(start.Add(-1), start, total, time.Time{}) || !clockCurrent(start, start, total, time.Time{}) {
		t.Fatal("original clock origin")
	}
}

func TestControlDataHistoricalPublicationBarrierNotAuthentication(t *testing.T) {
	makeState := func() *sourceState {
		s := memoryState()
		s.constructed, s.attempted, s.certificateRequested = true, true, true
		s.pair = &pairConfig{}
		s.clientValidity = validity{s.started.Add(-time.Hour), s.total}
		s.serverValidity = s.clientValidity
		s.ctx, s.cancel = context.WithCancel(context.Background())
		return s
	}
	before := makeState()
	before.retire()
	if _, err := before.finishPrepared(true, true); err == nil {
		t.Fatal("retirement before barrier")
	}
	after := makeState()
	data, err := after.finishPrepared(true, true)
	alias := Source{state: after}
	alias.RetireSource()
	if _, ok := data.Tuple(); err != nil || !ok || !after.retired || after.ctx.Err() == nil {
		t.Fatal("historical data after barrier")
	}
	if _, err := after.finishPrepared(true, true); err == nil {
		t.Fatal("second publication")
	}
	for _, complete := range []bool{false, true} {
		s := makeState()
		if _, err := s.finishPrepared(complete, false); err == nil || !s.retired {
			t.Fatal("incomplete closure")
		}
	}
}

func TestControlDataRejectsLiteralOutOfOrderPeersAndRoutes(t *testing.T) {
	d, _ := fixture(t)
	peers := bytes.Clone(d)
	a := bytes.Index(peers, []byte("front-a.internal.test"))
	b := bytes.Index(peers, []byte("front-b.internal.test"))
	if a < 0 || b < a {
		t.Fatal("fixture peer order")
	}
	copy(peers[a:a+21], "front-b.internal.test")
	copy(peers[b:b+21], "front-a.internal.test")
	if _, err := parseDescriptor(peers); err == nil {
		t.Fatal("reversed peers")
	}
	first := bytes.Clone(d[48 : len(d)-22])
	later := bytes.Clone(first)
	later[11] = 'z'
	later[14] = 'b'
	out := bytes.Clone(d[:48])
	out[47] = 2
	out = append(out, later...)
	out = append(out, first...)
	out = append(out, d[len(d)-22:]...)
	if _, err := parseDescriptor(out); err == nil {
		t.Fatal("reversed routes")
	}
}

// Zero is permitted configuration data; lexical appearance provides no
// freshness, authenticated comparison, history or frontend ownership.
func TestControlDataZeroGenerationIsData(t *testing.T) {
	d, _ := fixture(t)
	copy(d[8:40], strings.Repeat("0", 32))
	want, err := hex.DecodeString("4147434845434b313030303030303030303030303030303030303030303030303030303030303030fb1cbb6303fef567b601df7016a07e456abc8749215da8783abf316981c44fb41d987134086420d48b300a4cfda016ffc550a0bda6a6f20c58282db1b7d42dca")
	if err != nil {
		t.Fatal(err)
	}
	p, err := parsePair(d, "front-a.internal.test")
	if err != nil || !bytes.Equal(p.tuple[:], want) {
		t.Fatal("zero configuration data")
	}
}
