// SPDX-License-Identifier: BSD-3-Clause
package requestctx

// Pure bounded-memory fixtures only. No TLS/material constructor, listener,
// socket, engine or native process is invoked by these tests.
import (
	"bytes"
	"context"
	stdhex "encoding/hex"
	"encoding/json"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gonz0w/aegvium/internal/pairmodel"
)

func pairFixture(t *testing.T) (*pairedSnapshot, []byte, []byte) {
	t.Helper()
	b, err := os.ReadFile("testdata/pair_prepared.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Descriptor string `json:"descriptor_hex"`
		Prepared   string `json:"prepared_hex"`
	}
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	d, err := stdhex.DecodeString(f.Descriptor)
	if err != nil {
		t.Fatal(err)
	}
	want, err := stdhex.DecodeString(f.Prepared)
	if err != nil {
		t.Fatal(err)
	}
	s, err := newPairedSnapshot(d)
	if err != nil {
		t.Fatal(err)
	}
	if len(want) != 104 || !bytes.Equal(s.tuple[:], want) {
		t.Fatal("independent prepared literal mismatch")
	}
	return s, d, want
}
func pairHeader() []byte {
	return []byte("POST /_aegvium/m2-h1-1/pair HTTP/1.1\r\nHost: inspect.internal.test:8443\r\nContent-Length: 104\r\nConnection: close\r\n\r\n")
}
func TestPairSourceOwnedSnapshotAndPreparedTuple(t *testing.T) {
	s, raw, want := pairFixture(t)
	d, err := pairmodel.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	p, err := d.Projection()
	if err != nil {
		t.Fatal(err)
	}
	p.Routes[0].FrontendPeers[0] = "changed.internal.test"
	raw[0] = 'X'
	p2, err := d.Projection()
	if err != nil || p2.Routes[0].FrontendPeers[0] != "front-a.internal.test" || !bytes.Equal(s.tuple[:], want) {
		t.Fatal("input/projection alias")
	}
	if err := s.context.Record(context.Background(), Peer{}, Request{}, &Recorder{}); err != ErrPeer {
		t.Fatalf("prepared bytes minted Peer: %v", err)
	}
}
func TestPairSourceHTTPClassification(t *testing.T) {
	s, _, want := pairFixture(t)
	if got := pairHTTPStatus(s, pairHeader(), want); got != 200 {
		t.Fatalf("matching tuple: %d", got)
	}
	for _, n := range []int{103, 105} {
		p := make([]byte, n)
		copy(p, want)
		if got := pairHTTPStatus(s, pairHeader(), p); got != 400 {
			t.Fatalf("length %d: %d", n, got)
		}
	}
	for _, tc := range []struct{ at, status int }{{0, 400}, {8, 409}, {40, 409}, {72, 400}} {
		p := bytes.Clone(want)
		p[tc.at] ^= 1
		if got := pairHTTPStatus(s, pairHeader(), p); got != tc.status {
			t.Fatalf("mutation %d: %d", tc.at, got)
		}
	}
	p := bytes.Clone(want)
	p[8] = 'A'
	if pairHTTPStatus(s, pairHeader(), p) != 400 {
		t.Fatal("uppercase generation accepted")
	}
	for _, header := range []string{
		strings.Replace(string(pairHeader()), "Content-Length: 104\r\n", "Content-Length: 104\r\nContent-Length: 104\r\n", 1),
		strings.Replace(string(pairHeader()), "Content-Length: 104\r\n", "Content-Length: 104\r\nTransfer-Encoding: chunked\r\n", 1),
		strings.Replace(string(pairHeader()), "Connection: close", "Connection: keep-alive", 1),
		strings.Replace(string(pairHeader()), "/pair HTTP", "/pair?x=1 HTTP", 1),
		strings.Replace(string(pairHeader()), "inspect.internal.test:8443", "other.internal.test:8443", 1),
		strings.Repeat("x", 4097) + "\r\n\r\n",
	} {
		if got := pairHTTPStatus(s, []byte(header), want); got != 400 {
			t.Fatalf("malformed header: %d", got)
		}
	}
	if !bytes.HasSuffix(pairResponse(s, 200), want) || !bytes.HasSuffix(pairResponse(s, 409), []byte("Content-Length: 0\r\nConnection: close\r\n\r\n")) {
		t.Fatal("response framing")
	}
}

type pairReadFunc func([]byte) (int, error)

func (f pairReadFunc) Read(p []byte) (int, error) { return f(p) }

type pairWriteFunc func([]byte) (int, error)

func (f pairWriteFunc) Write(p []byte) (int, error) { return f(p) }
func TestPairSourceIOCommitChecks(t *testing.T) {
	until := time.Now().Add(time.Hour)
	for _, empty := range []int{99, 100} {
		calls := 0
		r := pairReadFunc(func(p []byte) (int, error) {
			calls++
			if calls <= empty {
				return 0, nil
			}
			p[0] = 'x'
			return 1, nil
		})
		var b [1]byte
		got := readPairExact(context.Background(), until, r, b[:])
		if got != (empty == 99) || calls != 100 {
			t.Fatalf("empty cutoff %d: %t/%d", empty, got, calls)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := pairReadFunc(func(p []byte) (int, error) { cancel(); p[0] = 'x'; return 1, nil })
	var b [1]byte
	if readPairExact(ctx, until, r, b[:]) {
		t.Fatal("cancelled completed read accepted")
	}
	ctx, cancel = context.WithCancel(context.Background())
	calls := 0
	w := pairWriteFunc(func(p []byte) (int, error) { calls++; cancel(); return len(p), nil })
	if writePairExact(ctx, until, w, b[:]) || calls != 1 {
		t.Fatal("cancelled completed write accepted/retried")
	}
	for _, n := range []int{-1, 2} {
		r = pairReadFunc(func([]byte) (int, error) { return n, nil })
		if readPairExact(context.Background(), until, r, b[:]) {
			t.Fatal("invalid read count")
		}
	}
	w = pairWriteFunc(func(p []byte) (int, error) { return len(p), io.ErrUnexpectedEOF })
	if writePairExact(context.Background(), until, w, b[:]) {
		t.Fatal("full write with error accepted")
	}
}

type pairMemoryConn struct {
	mu               sync.Mutex
	closes           int
	closeErr         error
	deadline         time.Time
	started, release chan struct{}
}

func (c *pairMemoryConn) Read(p []byte) (int, error) {
	if c.started != nil {
		close(c.started)
		<-c.release
	}
	return 0, io.EOF
}
func (c *pairMemoryConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *pairMemoryConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closes++
	return c.closeErr
}
func (c *pairMemoryConn) LocalAddr() net.Addr  { return nil }
func (c *pairMemoryConn) RemoteAddr() net.Addr { return nil }
func (c *pairMemoryConn) SetDeadline(v time.Time) error {
	c.mu.Lock()
	c.deadline = v
	c.mu.Unlock()
	return nil
}
func (c *pairMemoryConn) SetReadDeadline(v time.Time) error  { return c.SetDeadline(v) }
func (c *pairMemoryConn) SetWriteDeadline(v time.Time) error { return c.SetDeadline(v) }
func TestPairSourceCloseWaitsForJoinedCall(t *testing.T) {
	s, _, _ := pairFixture(t)
	o := &pairControlOwner{snapshot: s}
	r, err := o.reserve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	r2, err := o.reserve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := o.reserve(context.Background()); err == nil {
		t.Fatal("third reservation accepted")
	}
	other := &pairMemoryConn{}
	c := &pairMemoryConn{started: make(chan struct{}), release: make(chan struct{})}
	done := make(chan struct{})
	var release sync.Once
	t.Cleanup(func() { release.Do(func() { close(c.release) }); <-done })
	e, err := r.bind(c)
	if err != nil {
		close(done)
		t.Fatal(err)
	}
	copyHandle := *r
	if _, err := copyHandle.bind(other); err == nil || other.closes != 0 {
		close(done)
		t.Fatal("copy rebound/touched endpoint")
	}
	go func() { defer close(done); _, _ = e.Read(make([]byte, 1)) }()
	<-c.started
	if e.SetDeadline(r.state.total.Add(time.Hour)) != nil || !c.deadline.Equal(r.state.total) {
		t.Fatal("deadline extended")
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	r.state.finish()
	o.mu.Lock()
	retained := !r.state.released && o.seats == 2
	o.mu.Unlock()
	if !retained {
		t.Fatal("Close returned before read joined but seat released")
	}
	release.Do(func() { close(c.release) })
	<-done
	o.mu.Lock()
	released := r.state.released && o.seats == 1
	o.mu.Unlock()
	if !released || c.closes != 1 {
		t.Fatal("joined clean endpoint not released exactly once")
	}
	if e.Close() == nil || c.closes != 1 {
		t.Fatal("Close retried")
	}
	// The second reserved but unbound seat is deliberately retained, not refunded.
	if r2.state.released {
		t.Fatal("unbound reservation refunded")
	}
}
func TestPairSourceFailedCloseOrPoisonRetains(t *testing.T) {
	for _, poison := range []bool{false, true} {
		s, _, _ := pairFixture(t)
		o := &pairControlOwner{snapshot: s}
		r, err := o.reserve(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		c := &pairMemoryConn{closeErr: io.ErrUnexpectedEOF}
		e, err := r.bind(c)
		if err != nil {
			t.Fatal(err)
		}
		if poison {
			e.poison()
		}
		if e.Close() == nil {
			t.Fatal("uncertain close succeeded")
		}
		r.state.finish()
		wantCloses := 1
		if poison {
			wantCloses = 0
		}
		if r.state.released || o.seats != 1 || !o.retired || e.raw == nil || c.closes != wantCloses {
			t.Fatal("uncertainty not retained")
		}
		_ = e.Close()
		if c.closes != wantCloses {
			t.Fatal("uncertain close retried")
		}
	}
}
