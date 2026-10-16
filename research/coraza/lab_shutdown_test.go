// SPDX-License-Identifier: BSD-3-Clause
package spike

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type labShutdownListener struct{ closes atomic.Int32 }

func (l *labShutdownListener) Accept() (net.Conn, error) { return nil, net.ErrClosed }
func (l *labShutdownListener) Addr() net.Addr            { return nil }
func (l *labShutdownListener) Close() error              { l.closes.Add(1); return nil }

// No listener is opened and no WAF engine or request is constructed.
func TestLabShutdownDrainedServeFailure(t *testing.T) {
	serveErr := errors.New("controlled serve failure")
	waf := &labCountingCloser{}
	listener := &labShutdownListener{}
	f := &LabProxy{
		receiver: &proxyV1Listener{Listener: listener, done: make(chan struct{}), owned: make(map[net.Conn]bool)},
		servers:  []*http.Server{{}, {}},
		routes:   &labRouteOwner{active: &labRouteGeneration{waf: waf}},
	}
	f.engine.Store(true)
	for _, err := range []error{serveErr, http.ErrServerClosed} {
		done := make(chan error, 1)
		done <- err
		f.done = append(f.done, done)
	}
	if err := f.Close(); !errors.Is(err, serveErr) {
		t.Fatal("serve failure lost")
	}
	if waf.calls.Load() != 1 {
		t.Fatal("drained route generation was not retired")
	}
	if err := f.Close(); !errors.Is(err, serveErr) || waf.calls.Load() != 1 || listener.closes.Load() != 1 {
		t.Fatal("repeated close changed ownership or error")
	}
	if f.engine.Load() || !f.routes.closed || f.routes.active != nil {
		t.Fatal("closed resources remained available")
	}
}

type labShutdownServerStub struct {
	drainErr, closeErr error
	drains, closes     atomic.Int32
}

func (s *labShutdownServerStub) Shutdown(ctx context.Context) error {
	s.drains.Add(1)
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > 3*time.Second {
		return errors.New("shutdown guard changed")
	}
	return s.drainErr
}
func (s *labShutdownServerStub) Close() error { s.closes.Add(1); return s.closeErr }

type labShutdownCloser struct {
	err    error
	closes atomic.Int32
}

func (c *labShutdownCloser) Close() error { c.closes.Add(1); return c.err }

type labShutdownTransport struct{ closes atomic.Int32 }

func (c *labShutdownTransport) CloseIdleConnections() { c.closes.Add(1) }

func labShutdownResults(values ...error) []chan error {
	var results []chan error
	for _, err := range values {
		result := make(chan error, 1)
		result <- err
		results = append(results, result)
	}
	return results
}

func TestLabShutdownErrorOwnership(t *testing.T) {
	t.Run("drained-retirement-errors", func(t *testing.T) {
		serveA, serveB, retire := errors.New("serve a"), errors.New("serve b"), errors.New("retire")
		waf := &labShutdownCloser{err: retire}
		transport := &labShutdownTransport{}
		owner := &labRouteOwner{active: &labRouteGeneration{waf: waf, transports: []interface{ CloseIdleConnections() }{transport}}}
		a, b, receiver := &labShutdownServerStub{}, &labShutdownServerStub{}, &labShutdownCloser{}
		err := closeLabResources(receiver, owner, []labShutdownServer{a, b}, labShutdownResults(serveA, serveB))
		for _, cause := range []error{serveA, serveB, retire} {
			if !errors.Is(err, cause) {
				t.Fatal("independent cleanup error lost")
			}
		}
		if !errors.Is(owner.close(), retire) || !errors.Is(owner.close(), retire) {
			t.Fatal("owner close error lost on repetition")
		}
		if waf.closes.Load() != 1 || transport.closes.Load() != 1 || receiver.closes.Load() != 1 || a.drains.Load() != 1 || b.drains.Load() != 1 || a.closes.Load() != 0 || b.closes.Load() != 0 {
			t.Fatal("drained resources not retired exactly once")
		}
	})
	t.Run("failed-drain-retains-generation", func(t *testing.T) {
		drain, forced, serve, receive := errors.New("drain"), errors.New("force"), errors.New("serve"), errors.New("receiver")
		waf := &labShutdownCloser{}
		owner := &labRouteOwner{active: &labRouteGeneration{waf: waf}}
		a, b := &labShutdownServerStub{drainErr: drain, closeErr: forced}, &labShutdownServerStub{}
		err := closeLabResources(&labShutdownCloser{err: receive}, owner, []labShutdownServer{a, b}, labShutdownResults(serve, http.ErrServerClosed))
		for _, cause := range []error{drain, forced, serve, receive} {
			if !errors.Is(err, cause) {
				t.Fatal("shutdown failure overwritten")
			}
		}
		if !owner.stopping || owner.closed || waf.closes.Load() != 0 || a.drains.Load() != 1 || b.drains.Load() != 1 || a.closes.Load() != 1 || b.closes.Load() != 0 {
			t.Fatal("failed drain retired live state or skipped other shutdown")
		}
	})
	t.Run("normal-serve-completions", func(t *testing.T) {
		waf := &labShutdownCloser{}
		owner := &labRouteOwner{active: &labRouteGeneration{waf: waf}}
		if err := closeLabResources(&labShutdownCloser{}, owner, []labShutdownServer{&labShutdownServerStub{}, &labShutdownServerStub{}}, labShutdownResults(http.ErrServerClosed, net.ErrClosed)); err != nil || waf.closes.Load() != 1 {
			t.Fatal("normal shutdown changed")
		}
	})
}

func TestLabShutdownMissingJoin(t *testing.T) {
	closed := make(chan error)
	close(closed)
	for name, results := range map[string][]chan error{"absent": nil, "closed": {closed}, "stalled": {make(chan error)}} {
		t.Run(name, func(t *testing.T) {
			waf := &labShutdownCloser{}
			owner := &labRouteOwner{active: &labRouteGeneration{waf: waf}}
			done := make(chan error, 1)
			go func() {
				done <- closeLabResources(&labShutdownCloser{}, owner, []labShutdownServer{&labShutdownServerStub{}}, results)
			}()
			select {
			case err := <-done:
				if !errors.Is(err, errLabServerJoin) || waf.closes.Load() != 0 || owner.closed || !owner.stopping {
					t.Fatal("missing join retired generation or hid failure")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("join guard did not complete")
			}
		})
	}
}

func TestLabShutdownConcurrentClose(t *testing.T) {
	serve, retire := errors.New("serve"), errors.New("retire")
	waf := &labShutdownCloser{err: retire}
	listener := &labShutdownListener{}
	f := &LabProxy{receiver: &proxyV1Listener{Listener: listener, done: make(chan struct{}), owned: make(map[net.Conn]bool)},
		servers: []*http.Server{{}}, done: labShutdownResults(serve),
		routes: &labRouteOwner{active: &labRouteGeneration{waf: waf}}}
	const count = 16
	var callers sync.WaitGroup
	errorsSeen := make(chan error, count)
	for range count {
		callers.Add(1)
		go func() { defer callers.Done(); errorsSeen <- f.Close() }()
	}
	callers.Wait()
	close(errorsSeen)
	var first error
	for err := range errorsSeen {
		if !errors.Is(err, serve) || !errors.Is(err, retire) || (first != nil && err != first) {
			t.Fatal("concurrent close did not share completion error")
		}
		first = err
	}
	if waf.closes.Load() != 1 || listener.closes.Load() != 1 {
		t.Fatal("concurrent close repeated retirement")
	}
}

func TestLabShutdownLeaseRetirement(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	waf := &labShutdownCloser{}
	owner := &labRouteOwner{active: &labRouteGeneration{waf: waf, handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) { close(entered); <-release })}}
	served := make(chan struct{})
	go func() { owner.ServeHTTP(nil, nil); close(served) }()
	<-entered
	stopped := make(chan error, 1)
	go func() { stopped <- owner.close() }()
	// A held read lease must prevent the engine closer from running.
	select {
	case <-stopped:
		t.Fatal("retired a live generation")
	case <-time.After(20 * time.Millisecond):
	}
	if waf.closes.Load() != 0 {
		t.Fatal("engine closed under handler")
	}
	close(release)
	select {
	case err := <-stopped:
		if err != nil || waf.closes.Load() != 1 {
			t.Fatal("drained generation did not retire")
		}
	case <-time.After(time.Second):
		t.Fatal("generation did not drain")
	}
	<-served
	prepared := &labShutdownCloser{}
	if err := owner.replace(&labRouteGeneration{waf: prepared}); err == nil || prepared.closes.Load() != 1 {
		t.Fatal("late replacement not disposed")
	}
}

func TestLabShutdownReloadErrorCause(t *testing.T) {
	cause := errors.New("controlled retirement error")
	old, next := &labShutdownCloser{err: cause}, &labShutdownCloser{}
	owner := &labRouteOwner{active: &labRouteGeneration{waf: old}}
	err := owner.replace(&labRouteGeneration{waf: next})
	if !errors.Is(err, ErrLabReloadCleanup) || !errors.Is(err, cause) || old.closes.Load() != 1 || next.closes.Load() != 0 {
		t.Fatal("post-activation error lost its sentinel or cause")
	}
	if err := owner.close(); err != nil || next.closes.Load() != 1 {
		t.Fatal("activated generation ownership lost")
	}
}
