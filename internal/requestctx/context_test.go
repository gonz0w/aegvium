// SPDX-License-Identifier: BSD-3-Clause
package requestctx

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
	"unsafe"
)

const generation = "11111111111111111111111111111111"
const frontend = "frontend.example.test"
const application = "app.example.test"

func config() []Route {
	return []Route{{ID: "app", PublicName: application, Port: 443, FrontendPeers: []string{frontend}, PolicyPin: strings.Repeat("a", 64)}}
}
func snapshot(t *testing.T) *Snapshot {
	t.Helper()
	s, err := NewSnapshot(generation, config())
	if err != nil {
		t.Fatal("fixture snapshot rejected")
	}
	return s
}
func request() Request {
	return Request{Protocol: "HTTP/1.1", Method: "POST", Target: "/bucket//a%2Fb?x=2&x=%2F&z=", Body: []byte("x=a%2Fb&x=c"), Fields: []Field{
		{"Host", "APP.EXAMPLE.TEST:443"},
		{"Aegvium-Contract", "M2-H1/1"}, {"Aegvium-Route", "app"},
		{"Aegvium-Generation", generation}, {"Aegvium-Request", "fixture_1"},
		{"Aegvium-SNI", application}, {"Aegvium-Client", "192.0.2.8"},
		{"Content-Type", "application/x-www-form-urlencoded; charset=utf-8"},
		{"Content-Length", "11"}, {"X-Signed", "first  value"}, {"x-signed", "second value"},
		{"Authorization", "synthetic opaque public fixture"},
	}}
}
func set(r *Request, name, value string) {
	for i, f := range r.Fields {
		if strings.EqualFold(f.Name, name) {
			r.Fields[i].Value = value
			return
		}
	}
	r.Fields = append(r.Fields, Field{name, value})
}
func remove(r *Request, name string) {
	for i, f := range r.Fields {
		if strings.EqualFold(f.Name, name) {
			r.Fields = append(r.Fields[:i], r.Fields[i+1:]...)
			return
		}
	}
}
func record(s *Snapshot, r Request, dst *Recorder) error {
	return s.Record(context.Background(), Peer{frontend}, r, dst)
}

func TestDetachedContextAndConfigurationOwnership(t *testing.T) {
	cfg := config()
	s, err := NewSnapshot(generation, cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfg[0].ID = "replaced"
	cfg[0].PublicName = "foreign.example.test"
	cfg[0].FrontendPeers[0] = "foreign.example.test"
	in := request()
	original := request()
	dst := &Recorder{}
	if err := record(s, in, dst); err != nil {
		t.Fatal(err)
	}
	in.Body[0] = '!'
	in.Fields[0].Value = "foreign.example.test"
	in.Target = "/changed"
	rows := dst.Records()
	if len(rows) != 1 {
		t.Fatal("context count")
	}
	row := rows[0]
	if row.Route != "app" || row.Peer != frontend || row.Generation != generation || row.PolicyPin != strings.Repeat("a", 64) || row.SNI != application || row.Client != "192.0.2.8" || row.Target != original.Target || row.Authority != "APP.EXAMPLE.TEST:443" || !bytes.Equal(row.Body, original.Body) {
		t.Fatal("context/configuration fidelity lost")
	}
	var expected []Field
	for _, f := range original.Fields {
		if !strings.HasPrefix(strings.ToLower(f.Name), "aegvium-") {
			expected = append(expected, f)
		}
	}
	if !reflect.DeepEqual(row.Fields, expected) {
		t.Fatal("public header order, case or duplicate value changed")
	}
	rows[0].Body[0] = '!'
	rows[0].Fields[0].Value = "changed"
	rows[0].Route = "changed"
	again := dst.Records()
	if again[0].Route != "app" || again[0].Fields[0].Value != "APP.EXAMPLE.TEST:443" || !bytes.Equal(again[0].Body, original.Body) {
		t.Fatal("recorder exposed mutable retained state")
	}
}

func TestRetainedStringsDetachOversizedCallerBacking(t *testing.T) {
	backed := func(value string) string { return (value + strings.Repeat("z", 65536))[:len(value)] }
	assertDetached := func(got, original string) {
		t.Helper()
		if got != original || unsafe.StringData(got) == unsafe.StringData(original) {
			t.Fatal("retained bounded string aliases oversized caller backing")
		}
	}
	cfg := config()
	cfg[0].ID, cfg[0].PublicName, cfg[0].PolicyPin = backed("app"), backed(application), backed(strings.Repeat("a", 64))
	cfg[0].FrontendPeers[0] = backed(frontend)
	gen := backed(generation)
	s, err := NewSnapshot(gen, cfg)
	if err != nil {
		t.Fatal(err)
	}
	assertDetached(s.generation, gen)
	for id, route := range s.routes {
		assertDetached(id, cfg[0].ID)
		assertDetached(route.name, cfg[0].PublicName)
		assertDetached(route.pin, cfg[0].PolicyPin)
		for name := range route.peers {
			assertDetached(name, cfg[0].FrontendPeers[0])
		}
	}
	in := request()
	in.Target, in.Method, in.Protocol = backed(in.Target), backed(in.Method), backed(in.Protocol)
	in.Fields[0].Name, in.Fields[0].Value = backed("Host"), backed(in.Fields[0].Value)
	peer := Peer{backed(frontend)}
	dst := &Recorder{}
	if err := s.Record(context.Background(), peer, in, dst); err != nil {
		t.Fatal(err)
	}
	row := dst.Records()[0]
	for _, pair := range [][2]string{{row.Target, in.Target}, {row.Method, in.Method}, {row.Protocol, in.Protocol}, {row.Authority, in.Fields[0].Value}, {row.Fields[0].Name, in.Fields[0].Name}, {row.Fields[0].Value, in.Fields[0].Value}, {row.Peer, peer.identity}} {
		assertDetached(pair[0], pair[1])
	}
}

func TestParsedViewDoesNotProveOriginalWireRejection(t *testing.T) {
	in := request()
	in.Fields = append(in.Fields, Field{"Content-Length", "11"})
	if err := record(snapshot(t), in, &Recorder{}); err == nil {
		t.Fatal("visible duplicate length accepted")
	}
	// A frontend may already have removed that duplicate. The identical parsed
	// view cannot disclose its wire history; accepting it proves no raw rejection.
	in.Fields = in.Fields[:len(in.Fields)-1]
	if err := record(snapshot(t), in, &Recorder{}); err != nil {
		t.Fatal("ordinary parsed context rejected")
	}
}

func TestAdditionalConfigurationBounds(t *testing.T) {
	for _, n := range []int{32, 33} {
		cfg := config()
		cfg[0].ID = strings.Repeat("a", n)
		_, err := NewSnapshot(generation, cfg)
		if (err == nil) != (n == 32) {
			t.Fatal("route ID bound")
		}
	}
	for _, n := range []int{64, 65} {
		cfg := config()
		cfg[0].PolicyPin = strings.Repeat("a", n)
		_, err := NewSnapshot(generation, cfg)
		if (err == nil) != (n == 64) {
			t.Fatal("policy pin bound")
		}
	}
	for _, n := range []int{8, 9} {
		cfg := config()
		cfg[0].FrontendPeers = nil
		for i := 0; i < n; i++ {
			cfg[0].FrontendPeers = append(cfg[0].FrontendPeers, "peer"+strconv.Itoa(i)+".example.test")
		}
		_, err := NewSnapshot(generation, cfg)
		if (err == nil) != (n == 8) {
			t.Fatal("peer count bound")
		}
	}
	var large []Route
	for i := 0; i < 8; i++ {
		c := config()[0]
		c.ID = "app" + strconv.Itoa(i)
		c.PublicName = "app" + strconv.Itoa(i) + ".example.test"
		c.FrontendPeers = nil
		for j := 0; j < 8; j++ {
			c.FrontendPeers = append(c.FrontendPeers, string(rune('a'+j))+longDNS(253)[1:])
		}
		large = append(large, c)
	}
	if _, err := NewSnapshot(generation, large); err == nil {
		t.Fatal("oversized retained configuration accepted")
	}
}

func TestContextRejectionsNeverRecord(t *testing.T) {
	tests := map[string]func(*Request){
		"contract":              func(r *Request) { set(r, "Aegvium-Contract", "future") },
		"missing":               func(r *Request) { remove(r, "Aegvium-SNI") },
		"duplicate-context":     func(r *Request) { r.Fields = append(r.Fields, Field{"aEgViUm-rOuTe", "app"}) },
		"unknown-context":       func(r *Request) { r.Fields = append(r.Fields, Field{"Aegvium-Allow", "true"}) },
		"route":                 func(r *Request) { set(r, "Aegvium-Route", "other") },
		"generation":            func(r *Request) { set(r, "Aegvium-Generation", strings.Repeat("2", 32)) },
		"sni":                   func(r *Request) { set(r, "Aegvium-SNI", "other.example.test") },
		"sni-case":              func(r *Request) { set(r, "Aegvium-SNI", "APP.EXAMPLE.TEST") },
		"client-ipv6":           func(r *Request) { set(r, "Aegvium-Client", "2001:db8::1") },
		"client-noncanonical":   func(r *Request) { set(r, "Aegvium-Client", "192.000.2.8") },
		"authority":             func(r *Request) { set(r, "Host", "foreign.example.test") },
		"authority-port":        func(r *Request) { set(r, "Host", "app.example.test:8443") },
		"authority-empty-port":  func(r *Request) { set(r, "Host", "app.example.test:") },
		"authority-zero-prefix": func(r *Request) { set(r, "Host", "app.example.test:0443") },
		"authority-dot":         func(r *Request) { set(r, "Host", "app.example.test.") },
		"authority-userinfo":    func(r *Request) { set(r, "Host", "x@app.example.test") },
		"duplicate-host":        func(r *Request) { r.Fields = append(r.Fields, Field{"host", application}) },
		"duplicate-length":      func(r *Request) { r.Fields = append(r.Fields, Field{"content-length", "11"}) },
		"length-overflow":       func(r *Request) { set(r, "Content-Length", "18446744073709551616") },
		"length-leading-zero":   func(r *Request) { set(r, "Content-Length", "011") },
		"length-mismatch":       func(r *Request) { set(r, "Content-Length", "12") },
		"length-missing":        func(r *Request) { remove(r, "Content-Length") },
		"content-type":          func(r *Request) { set(r, "Content-Type", "application/grpc") },
		"charset":               func(r *Request) { set(r, "Content-Type", "application/json; charset=other") },
		"method":                func(r *Request) { r.Method = "CONNECT" },
		"protocol":              func(r *Request) { r.Protocol = "HTTP/2.0" },
		"absolute-target":       func(r *Request) { r.Target = "https://app.example.test/" },
		"fragment":              func(r *Request) { r.Target = "/x#fragment" },
		"bad-escape":            func(r *Request) { r.Target = "/x%2" },
		"target-control":        func(r *Request) { r.Target = "/x\r\n" },
		"header-control":        func(r *Request) { r.Fields = append(r.Fields, Field{"X-Other", "x\r\ny"}) },
		"header-name":           func(r *Request) { r.Fields = append(r.Fields, Field{"invalid name", "x"}) },
		"keepalive":             func(r *Request) { set(r, "Connection", "keep-alive") },
		"signed-stream":         func(r *Request) { set(r, "X-Amz-Content-Sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD") },
	}
	for _, name := range []string{"Transfer-Encoding", "Content-Encoding", "Trailer", "TE", "Expect", "Upgrade", "Proxy-Connection", "Keep-Alive", "Forwarded", "X-Forwarded-For", "X-Real-IP"} {
		tests[name] = func(r *Request) { r.Fields = append(r.Fields, Field{name, "unsupported"}) }
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			in := request()
			change(&in)
			dst := &Recorder{}
			if err := record(snapshot(t), in, dst); err == nil || len(dst.Records()) != 0 {
				t.Fatal("invalid context recorded")
			}
		})
	}
}

func TestPeerAndRouteIsolation(t *testing.T) {
	s := snapshot(t)
	for _, peer := range []Peer{{}, {"foreign.example.test"}, {"FRONTEND.EXAMPLE.TEST"}} {
		dst := &Recorder{}
		if err := s.Record(context.Background(), peer, request(), dst); !errors.Is(err, ErrPeer) || len(dst.Records()) != 0 {
			t.Fatal("unverified/foreign peer admitted")
		}
	}
	cfg := append(config(), Route{ID: "other", PublicName: "other.example.test", Port: 8443, FrontendPeers: []string{"other-frontend.example.test"}, PolicyPin: strings.Repeat("b", 64)})
	s, err := NewSnapshot(generation, cfg)
	if err != nil {
		t.Fatal(err)
	}
	in := request()
	set(&in, "Aegvium-Route", "other")
	set(&in, "Aegvium-SNI", "other.example.test")
	set(&in, "Host", "other.example.test:8443")
	if err := record(s, in, &Recorder{}); !errors.Is(err, ErrPeer) {
		t.Fatal("route changed peer authority")
	}
	dst := &Recorder{}
	if err := s.Record(context.Background(), Peer{"other-frontend.example.test"}, in, dst); err != nil {
		t.Fatal(err)
	}
	if row := dst.Records()[0]; row.Route != "other" || row.PolicyPin != strings.Repeat("b", 64) || row.Authority != "other.example.test:8443" {
		t.Fatal("route policy spliced")
	}
	set(&in, "Host", "other.example.test")
	if err := s.Record(context.Background(), Peer{"other-frontend.example.test"}, in, &Recorder{}); !errors.Is(err, ErrAuthority) {
		t.Fatal("nondefault port omitted")
	}
}

func TestGetHeadAndDefaultPort(t *testing.T) {
	for _, method := range []string{"GET", "HEAD"} {
		for _, length := range []string{"absent", "0"} {
			in := request()
			in.Method = method
			in.Body = nil
			remove(&in, "Content-Type")
			set(&in, "Host", application)
			if length == "absent" {
				remove(&in, "Content-Length")
			} else {
				set(&in, "Content-Length", length)
			}
			if err := record(snapshot(t), in, &Recorder{}); err != nil {
				t.Fatal("bodyless method rejected")
			}
			in.Body = []byte("x")
			set(&in, "Content-Length", "1")
			if err := record(snapshot(t), in, &Recorder{}); err == nil {
				t.Fatal("bodyless method acquired body")
			}
		}
	}
}

// This independent serializer measures the supplied parsed view, never claims
// those bytes were an original public wire request after frontend normalization.
func publicViewBytes(in Request) int {
	var b strings.Builder
	b.WriteString(in.Method + " " + in.Target + " " + in.Protocol + "\r\n")
	for _, f := range in.Fields {
		if !strings.HasPrefix(strings.ToLower(f.Name), "aegvium-") {
			b.WriteString(f.Name + ": " + f.Value + "\r\n")
		}
	}
	b.WriteString("\r\n")
	return b.Len()
}

func TestReachableInputBounds(t *testing.T) {
	for _, n := range []int{MaxBody, MaxBody + 1} {
		in := request()
		in.Body = bytes.Repeat([]byte("x"), n)
		set(&in, "Content-Length", strconv.Itoa(n))
		err := record(snapshot(t), in, &Recorder{})
		if (err == nil) != (n == MaxBody) {
			t.Fatal("body bound")
		}
	}
	for _, n := range []int{MaxTarget, MaxTarget + 1} {
		in := request()
		in.Target = "/" + strings.Repeat("x", n-1)
		err := record(snapshot(t), in, &Recorder{})
		if (err == nil) != (n == MaxTarget) {
			t.Fatal("target bound")
		}
	}
	for _, n := range []int{MaxFields, MaxFields + 1} {
		in := request()
		for len(in.Fields) < n {
			in.Fields = append(in.Fields, Field{"X-Pad", ""})
		}
		err := record(snapshot(t), in, &Recorder{})
		if (err == nil) != (n == MaxFields) {
			t.Fatal("field count bound")
		}
	}
	for _, n := range []int{4096, 4097} {
		in := request()
		in.Fields = append(in.Fields, Field{"X-Pad", ""})
		in.Fields[len(in.Fields)-1].Value = strings.Repeat("x", n-publicViewBytes(in))
		if publicViewBytes(in) != n {
			t.Fatal("independent view-size oracle")
		}
		err := record(snapshot(t), in, &Recorder{})
		if (err == nil) != (n == 4096) {
			t.Fatal("parsed public-view bound")
		}
	}
	for _, n := range []int{64, 65} {
		in := request()
		set(&in, "Aegvium-Request", strings.Repeat("x", n))
		err := record(snapshot(t), in, &Recorder{})
		if (err == nil) != (n == 64) {
			t.Fatal("correlation bound")
		}
	}
}

func longDNS(n int) string {
	var labels []string
	for n > 63 {
		labels = append(labels, strings.Repeat("a", 63))
		n -= 64
	}
	return strings.Join(append(labels, strings.Repeat("b", n)), ".")
}

func TestSnapshotConfigurationBoundsAndAmbiguity(t *testing.T) {
	for _, n := range []int{253, 254} {
		cfg := config()
		cfg[0].PublicName = longDNS(n)
		s, err := NewSnapshot(generation, cfg)
		if (err == nil) != (n == 253) {
			t.Fatal("DNS total bound")
		}
		if s != nil {
			in := request()
			set(&in, "Host", cfg[0].PublicName)
			set(&in, "Aegvium-SNI", cfg[0].PublicName)
			if err := record(s, in, &Recorder{}); err != nil {
				t.Fatal("maximum DNS context rejected")
			}
		}
	}
	for _, n := range []int{8, 9} {
		var cfg []Route
		for i := 0; i < n; i++ {
			c := config()[0]
			c.ID = "app" + strconv.Itoa(i)
			c.PublicName = "app" + strconv.Itoa(i) + ".example.test"
			cfg = append(cfg, c)
		}
		_, err := NewSnapshot(generation, cfg)
		if (err == nil) != (n == 8) {
			t.Fatal("route count bound")
		}
	}
	for _, n := range []int{32, 33} {
		_, err := NewSnapshot(strings.Repeat("1", n), config())
		if (err == nil) != (n == 32) {
			t.Fatal("generation bound")
		}
	}
	tests := map[string]func([]Route){
		"duplicate-id":        func(c []Route) { c[1].ID = c[0].ID },
		"duplicate-authority": func(c []Route) { c[1].PublicName = c[0].PublicName },
		"zero-port":           func(c []Route) { c[0].Port = 0 },
		"wildcard":            func(c []Route) { c[0].PublicName = "*.example.test" },
		"trailing-dot":        func(c []Route) { c[0].PublicName = application + "." },
		"IP":                  func(c []Route) { c[0].PublicName = "192.0.2.1" },
		"long-label":          func(c []Route) { c[0].PublicName = strings.Repeat("a", 64) + ".test" },
		"bad-policy":          func(c []Route) { c[0].PolicyPin = strings.Repeat("A", 64) },
		"duplicate-peer":      func(c []Route) { c[0].FrontendPeers = []string{frontend, frontend} },
		"no-peer":             func(c []Route) { c[0].FrontendPeers = nil },
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := append(config(), Route{ID: "other", PublicName: "other.example.test", Port: 443, PolicyPin: strings.Repeat("b", 64), FrontendPeers: []string{frontend}})
			change(cfg)
			if _, err := NewSnapshot(generation, cfg); err == nil {
				t.Fatal("invalid snapshot accepted")
			}
		})
	}
	if _, err := NewSnapshot(generation, nil); err == nil {
		t.Fatal("empty snapshot")
	}
}

func waitBusy(t *testing.T, s *Snapshot) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if !s.mu.TryLock() {
			return
		}
		s.mu.Unlock()
		runtime.Gosched()
	}
	t.Fatal("recording did not reach held consumer")
}
func result(t *testing.T, ch <-chan error) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(2 * time.Second):
		t.Fatal("owned operation did not finish")
		return nil
	}
}

func TestCancellationAtHeldPublication(t *testing.T) {
	s := snapshot(t)
	dst := &Recorder{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dst.mu.Lock()
	done := make(chan error, 1)
	go func() { done <- s.Record(ctx, Peer{frontend}, request(), dst) }()
	waitBusy(t, s)
	cancel()
	dst.mu.Unlock()
	if err := result(t, done); !errors.Is(err, context.Canceled) || len(dst.Records()) != 0 {
		t.Fatal("cancelled context published")
	}
}

func TestRetirementSerializesAndNeverRevives(t *testing.T) {
	s := snapshot(t)
	dst := &Recorder{}
	dst.mu.Lock()
	done := make(chan error, 1)
	go func() { done <- record(s, request(), dst) }()
	waitBusy(t, s)
	retired := make(chan struct{})
	go func() { s.Retire(); close(retired) }()
	select {
	case <-retired:
		t.Fatal("retirement passed an active publication")
	default:
	}
	dst.mu.Unlock()
	if err := result(t, done); err != nil {
		t.Fatal(err)
	}
	select {
	case <-retired:
	case <-time.After(2 * time.Second):
		t.Fatal("retirement did not finish")
	}
	if err := record(s, request(), dst); !errors.Is(err, ErrRetired) || len(dst.Records()) != 1 {
		t.Fatal("retired context admitted")
	}
	fresh, err := NewSnapshot(strings.Repeat("2", 32), config())
	if err != nil {
		t.Fatal(err)
	}
	if err := record(fresh, request(), &Recorder{}); !errors.Is(err, ErrGeneration) {
		t.Fatal("old generation reused against fresh snapshot")
	}
}

func TestBoundedAdmissionAndRecorder(t *testing.T) {
	s := snapshot(t)
	dst := &Recorder{}
	dst.mu.Lock()
	done := make(chan error, MaxRecords)
	for i := 0; i < MaxRecords; i++ {
		go func() { done <- record(s, request(), dst) }()
	}
	deadline := time.Now().Add(2 * time.Second)
	for len(s.admission) != MaxRecords && time.Now().Before(deadline) {
		runtime.Gosched()
	}
	if len(s.admission) != MaxRecords {
		dst.mu.Unlock()
		t.Fatal("workers did not reach bounded admission")
	}
	if err := record(s, request(), &Recorder{}); !errors.Is(err, ErrCapacity) {
		dst.mu.Unlock()
		t.Fatal("capacity waited or admitted")
	}
	dst.mu.Unlock()
	for i := 0; i < MaxRecords; i++ {
		if err := result(t, done); err != nil {
			t.Fatal(err)
		}
	}
	if len(dst.Records()) != MaxRecords {
		t.Fatal("lost recording")
	}
	if err := record(s, request(), dst); !errors.Is(err, ErrCapacity) || len(dst.Records()) != MaxRecords {
		t.Fatal("recorder overflow or eviction")
	}
}

func TestInvalidAndCancelledInvocation(t *testing.T) {
	s := snapshot(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	dst := &Recorder{}
	if !errors.Is(s.Record(ctx, Peer{frontend}, request(), dst), context.Canceled) || len(dst.Records()) != 0 {
		t.Fatal("cancelled dispatch")
	}
	if s.Record(nil, Peer{frontend}, request(), dst) != ErrInput || s.Record(context.Background(), Peer{frontend}, request(), nil) != ErrInput {
		t.Fatal("nil invocation")
	}
	var absent *Snapshot
	if absent.Record(context.Background(), Peer{frontend}, request(), dst) != ErrInput {
		t.Fatal("nil snapshot")
	}
	absent.Retire()
}

func FuzzParsedContext(f *testing.F) {
	f.Add("/bucket//a%2Fb?x=2&x=1", application, generation, []byte("x=1"))
	f.Add("/", application, strings.Repeat("2", 32), []byte{})
	f.Fuzz(func(t *testing.T, targetValue, host, gen string, body []byte) {
		in := request()
		in.Target = targetValue
		in.Body = body
		set(&in, "Host", host)
		set(&in, "Aegvium-Generation", gen)
		set(&in, "Content-Length", strconv.Itoa(len(body)))
		dst := &Recorder{}
		err := record(snapshot(t), in, dst)
		rows := dst.Records()
		if err != nil {
			if len(rows) != 0 {
				t.Fatal("rejection recorded")
			}
			return
		}
		if len(rows) != 1 || rows[0].Target != targetValue || rows[0].Authority != host || !bytes.Equal(rows[0].Body, body) || len(body) > MaxBody || len(targetValue) > MaxTarget {
			t.Fatal("accepted context lost its binding")
		}
	})
}
