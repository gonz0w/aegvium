// SPDX-License-Identifier: BSD-3-Clause
package spike

import (
	"errors"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"
)

type labServeFunc func(net.Listener) error

func (f labServeFunc) Serve(listener net.Listener) error { return f(listener) }

func labNoticeClosed(notice <-chan struct{}) bool {
	select {
	case <-notice:
		return true
	default:
		return false
	}
}

func TestLabSupervisionCompletion(t *testing.T) {
	for _, cause := range []error{nil, errors.New("controlled serve failure"), http.ErrServerClosed, net.ErrClosed} {
		f := &LabProxy{}
		f.engine.Store(true)
		done := make(chan error, 1)
		f.serveLabHTTP(labServeFunc(func(net.Listener) error { return cause }), nil, done)
		// Obtain notification after completion too: late subscribers see failure.
		notice := f.Failed()
		if !labNoticeClosed(notice) || f.engine.Load() || f.Failed() != notice {
			t.Fatal("unexpected completion did not drop readiness and broadcast")
		}
		select {
		case got := <-done:
			if got != cause {
				t.Fatal("original Serve result changed")
			}
		default:
			t.Fatal("notification consumed the shutdown result")
		}
	}
}

func TestLabSupervisionExpectedShutdown(t *testing.T) {
	f := &LabProxy{}
	f.engine.Store(true)
	notice := f.Failed()
	f.beginLabClose()
	for _, cause := range []error{nil, http.ErrServerClosed, net.ErrClosed} {
		done := make(chan error, 1)
		f.serveLabHTTP(labServeFunc(func(net.Listener) error { return cause }), nil, done)
		if <-done != cause || labNoticeClosed(notice) || f.engine.Load() {
			t.Fatal("requested shutdown reported a new failure or lost completion")
		}
	}
}

func TestLabSupervisionConcurrentFailureCleanup(t *testing.T) {
	dataErr, healthErr := errors.New("data serve"), errors.New("health serve")
	waf, listener := &labShutdownCloser{}, &labShutdownListener{}
	f := &LabProxy{receiver: &proxyV1Listener{Listener: listener, done: make(chan struct{}), owned: make(map[net.Conn]bool)},
		servers: []*http.Server{{}, {}}, done: []chan error{make(chan error, 1), make(chan error, 1)},
		routes: &labRouteOwner{active: &labRouteGeneration{waf: waf}}}
	f.engine.Store(true)
	release := make(chan struct{})
	for i, cause := range []error{dataErr, healthErr} {
		go f.serveLabHTTP(labServeFunc(func(net.Listener) error { <-release; return cause }), nil, f.done[i])
	}
	notices := make(chan (<-chan struct{}), 16)
	var subscribers sync.WaitGroup
	for range cap(notices) {
		subscribers.Add(1)
		go func() { defer subscribers.Done(); notices <- f.Failed() }()
	}
	subscribers.Wait()
	close(notices)
	close(release)
	for notice := range notices {
		select {
		case <-notice:
			if f.engine.Load() {
				t.Fatal("failure broadcast preceded readiness drop")
			}
		case <-time.After(time.Second):
			t.Fatal("failure notification did not wake subscriber")
		}
	}
	err := f.Close()
	if !errors.Is(err, dataErr) || !errors.Is(err, healthErr) || waf.closes.Load() != 1 || listener.closes.Load() != 1 {
		t.Fatal("failure observation stole completion or prevented drained cleanup")
	}
	if f.Close() != err || !labNoticeClosed(f.Failed()) {
		t.Fatal("shutdown lost prior failure or changed shared completion")
	}
}

func TestLabSupervisionCloseExitRace(t *testing.T) {
	for range 64 {
		f := &LabProxy{}
		f.engine.Store(true)
		notice := f.Failed()
		var operations sync.WaitGroup
		operations.Add(2)
		go func() { defer operations.Done(); f.beginLabClose() }()
		go func() { defer operations.Done(); f.recordLabServerExit() }()
		operations.Wait()
		observed := labNoticeClosed(notice)
		// Later expected completions cannot change the established outcome.
		f.recordLabServerExit()
		if f.engine.Load() || f.Failed() != notice || labNoticeClosed(notice) != observed {
			t.Fatal("close/exit race changed readiness or terminal notification")
		}
	}
}
