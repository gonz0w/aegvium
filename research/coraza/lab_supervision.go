// SPDX-License-Identifier: BSD-3-Clause
package spike

import (
	"net"
	"sync"
)

type labServeState struct {
	mu      sync.Mutex
	closing bool
	failed  bool
	notice  chan struct{}
}

// Failed broadcasts an unexpected HTTP Serve completion. It carries no error
// content and does not replace Close or its single-consumer completion receipts.
// This is lab lifecycle instrumentation, not a supported appliance API.
func (f *LabProxy) Failed() <-chan struct{} {
	f.serve.mu.Lock()
	defer f.serve.mu.Unlock()
	if f.serve.notice == nil {
		f.serve.notice = make(chan struct{})
	}
	return f.serve.notice
}

func (f *LabProxy) recordLabServerExit() {
	f.serve.mu.Lock()
	defer f.serve.mu.Unlock()
	f.engine.Store(false)
	if f.serve.closing || f.serve.failed {
		return
	}
	f.serve.failed = true
	if f.serve.notice == nil {
		f.serve.notice = make(chan struct{})
	}
	close(f.serve.notice)
}

func (f *LabProxy) beginLabClose() {
	f.serve.mu.Lock()
	defer f.serve.mu.Unlock()
	f.serve.closing = true
	f.engine.Store(false)
}

func (f *LabProxy) serveLabHTTP(server interface{ Serve(net.Listener) error }, listener net.Listener, done chan error) {
	err := server.Serve(listener)
	f.recordLabServerExit()
	done <- err
}
