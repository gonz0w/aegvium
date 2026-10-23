//go:build openbsd && aegvium_transport_source && aegvium_engine_source && no_fs_access

// SPDX-License-Identifier: BSD-3-Clause
package bodyowner

import (
	"context"
	"github.com/gonz0w/aegvium/internal/requestctx"
	"io"
	"sync/atomic"
)

// InspectorEngineSource binds the actual pinned engine and retirement owner to
// one startup generation. It issues no request, authentication or allow handle.
type InspectorEngineSource struct {
	owner         *Owner
	generation    *Generation
	failedData    *requestctx.DataSessionSource
	failedInbound *Inbound
	diagnostics   sourceDiagnostics
}

var inspectorEngineSource struct {
	attempted atomic.Bool
	held      *InspectorEngineSource
}

// PrepareInspectorEngineSource is called only by the single-threaded source
// entry. Generation is configuration from inherited bootstrap, not authority.
// Keep partial engine state on failure; S alone can reclaim the whole process.
func PrepareInspectorEngineSource(generation, expectedPolicy string) (*InspectorEngineSource, error) {
	if !inspectorEngineSource.attempted.CompareAndSwap(false, true) {
		return nil, ErrStopped
	}
	s := &InspectorEngineSource{}
	inspectorEngineSource.held = s
	if expectedPolicy != policyPin() {
		return nil, errPolicyPreparation
	}
	var err error
	s.owner, err = newPinnedEngineOwner()
	if err != nil {
		return nil, errPolicyPreparation
	}
	s.generation, err = s.owner.NewGeneration(generation)
	if err != nil {
		s.owner.Stop()
		return nil, errPolicyPreparation
	}
	return s, nil
}

// RetireControlSource consumes the actual startup-owned channel. An ACK means
// admission retirement only; successful return is not physical reclamation.
func (s *InspectorEngineSource) RetireControlSource(channel io.ReadWriteCloser) error {
	if s == nil || s.owner == nil || s.generation == nil {
		return ErrInput
	}
	out := s.generation.retireControl(channel)
	if !out.Retired || !out.AckWritten || !out.EndpointClosed || out.Fault != controlNone {
		return ErrStopped
	}
	return nil
}

func (s *InspectorEngineSource) StopSource() {
	if s != nil && s.owner != nil {
		s.owner.Stop()
		if s.generation != nil {
			s.generation.Retire()
		}
	}
}

// OperationalReportSource is a read-only copy of actual private DATA ownership.
// It opens no health endpoint and carries no readiness or forwarding authority.
func (s *InspectorEngineSource) OperationalReportSource() string {
	if s == nil {
		return (*Owner)(nil).OperationalReport()
	}
	return s.owner.OperationalReport()
}

// WaitDataSource joins known jobs/cache only. Success is not process or full
// network reclamation proof; S still owns physical wait/reaping.
func (s *InspectorEngineSource) WaitDataSource(ctx context.Context) error {
	if s == nil || s.owner == nil || ctx == nil {
		return ErrInput
	}
	state := s.owner.state
	state.mu.Lock()
	jobs := make([]<-chan struct{}, 0, len(state.jobs))
	for j := range state.jobs {
		jobs = append(jobs, j.done)
	}
	state.mu.Unlock()
	for _, done := range jobs {
		select {
		case <-done:
		case <-ctx.Done():
			return ErrStopped
		}
	}
	state.mu.Lock()
	clean := len(state.jobs) == 0 && state.engine.references == 0 && s.failedData == nil && s.failedInbound == nil
	cache := state.engine.cacheDone
	state.mu.Unlock()
	if !clean {
		return ErrStopped
	}
	select {
	case <-cache:
	case <-ctx.Done():
		return ErrStopped
	}
	state.mu.Lock()
	clean = state.engine.cacheReleased && !state.engine.cacheUncertain
	state.mu.Unlock()
	if !clean {
		return ErrStopped
	}
	return nil
}
