//go:build openbsd && aegvium_transport_source && aegvium_engine_source && no_fs_access

// SPDX-License-Identifier: BSD-3-Clause
package bodyowner

import (
	"io"
	"sync/atomic"
)

// InspectorEngineSource binds the actual pinned engine and retirement owner to
// one startup generation. It issues no request, authentication or allow handle.
type InspectorEngineSource struct {
	owner      *Owner
	generation *Generation
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
