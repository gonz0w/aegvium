//go:build aegvium_transport_source

// SPDX-License-Identifier: BSD-3-Clause
package requestctx

// Only the actual endpoint ownership wrappers run, with finite memory net.Conn
// intercepts. Never call a TLS/material/listener/Dial constructor in this file.
import (
	"context"
	"io"
	"sync"
	"testing"
	"time"
)

func dataMemorySession(raw *pairMemoryConn) *DataSessionSource {
	s := &DataSessionSource{accepted: time.Now()}
	s.inbound = &dataConn{owner: s, raw: raw}
	return s
}

func dataSourceReached(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("finite memory-call join failed")
	}
}

func TestDataSourceCloseMustJoinActualMemoryCall(t *testing.T) {
	c := &pairMemoryConn{started: make(chan struct{}), release: make(chan struct{})}
	s := dataMemorySession(c)
	done := make(chan struct{})
	var free sync.Once
	release := func() { free.Do(func() { close(c.release) }) }
	t.Cleanup(func() { release(); dataSourceReached(t, done) })
	go func() { defer close(done); _, _ = s.inbound.Read(make([]byte, 1)) }()
	dataSourceReached(t, c.started)
	if s.CloseDataSource() != nil {
		release()
		dataSourceReached(t, done)
		t.Fatal("memory close")
	}
	if certain, _ := s.CleanupDataSource(); certain {
		release()
		dataSourceReached(t, done)
		t.Fatal("Close return refunded active read")
	}
	release()
	dataSourceReached(t, done)
	if certain, unsafe := s.CleanupDataSource(); !certain || unsafe || c.closes != 1 {
		t.Fatal("joined known endpoint not certain")
	}
	if s.CloseDataSource() == nil || c.closes != 1 {
		t.Fatal("cleanup retried")
	}
	if _, err := s.inbound.Write([]byte("x")); err == nil {
		t.Fatal("new IO after close claim")
	}
}

type invalidDataConn struct {
	*pairMemoryConn
	reads int
}

func (c *invalidDataConn) Read(p []byte) (int, error) { c.reads++; return len(p) + 1, nil }

func TestDataSourceInvalidCountPoisonsWithoutSpeculativeClose(t *testing.T) {
	raw := &invalidDataConn{pairMemoryConn: &pairMemoryConn{}}
	s := &DataSessionSource{accepted: time.Now()}
	s.inbound = &dataConn{owner: s, raw: raw}
	if _, err := s.inbound.Read(make([]byte, 1)); err == nil {
		t.Fatal("invalid count accepted")
	}
	if certain, unsafe := s.CleanupDataSource(); certain || !unsafe {
		t.Fatal("invalid raw call not retained unsafe")
	}
	_ = s.CloseDataSource()
	_, _ = s.inbound.Read(make([]byte, 1))
	if raw.closes != 0 || raw.reads != 1 {
		t.Fatal("new call after unsafe ownership")
	}
}

func TestDataSourceCloseErrorRemainsOwned(t *testing.T) {
	c := &pairMemoryConn{closeErr: io.ErrUnexpectedEOF}
	s := dataMemorySession(c)
	if s.CloseDataSource() == nil {
		t.Fatal("failed close accepted")
	}
	if certain, _ := s.CleanupDataSource(); certain {
		t.Fatal("failed endpoint refunded")
	}
	_ = s.CloseDataSource()
	if c.closes != 1 {
		t.Fatal("failed Close retried")
	}
}

func TestDataSourceLateDialResultCannotEscapeCleanup(t *testing.T) {
	for _, fail := range []bool{false, true} {
		in, out := &pairMemoryConn{}, &pairMemoryConn{}
		if fail {
			out.closeErr = io.ErrUnexpectedEOF
		}
		s := dataMemorySession(in)
		s.dialing = true
		if s.CloseDataSource() != nil {
			t.Fatal("initial close")
		}
		if certain, _ := s.CleanupDataSource(); certain {
			t.Fatal("pending Dial treated as absence")
		}
		e, closing := s.adoptDialResult(out)
		if !closing || e == nil || in.closes != 1 || out.closes != 1 {
			t.Fatal("late owned handle lost/duplicated")
		}
		if certain, _ := s.CleanupDataSource(); certain == fail {
			t.Fatal("late close failure/return misclassified")
		}
		_ = s.CloseDataSource()
		if out.closes != 1 {
			t.Fatal("late endpoint Close retried")
		}
	}
}

func TestDataSourceZeroSessionCannotCreateAuthenticationOrEffect(t *testing.T) {
	s := &DataSessionSource{}
	if _, err := s.ReadDataSource(context.Background()); err == nil {
		t.Fatal("zero session authenticated")
	}
	if attempted, written, err := s.ExchangeDataSource(context.Background()); attempted || written || err == nil {
		t.Fatal("zero session forwarded")
	}
	if s.RejectDataSource(context.Background(), 503) == nil {
		t.Fatal("zero session wrote response")
	}
	if certain, _ := s.CleanupDataSource(); certain {
		t.Fatal("missing handles proved cleanup")
	}
}
