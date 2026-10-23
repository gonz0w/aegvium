//go:build openbsd && aegvium_transport_source && aegvium_engine_source && no_fs_access

// SPDX-License-Identifier: BSD-3-Clause
package bodyowner

import (
	"context"
	"time"

	"github.com/gonz0w/aegvium/internal/requestctx"
)

var _ dataSession = (*requestctx.DataSessionSource)(nil)

// Carries the actual accepted deadline without an extra per-request parent
// timer. beginOwned creates and later cancels the job's one private timer.
type acceptedDataContext struct {
	context.Context
	until time.Time
}

func (c acceptedDataContext) Deadline() (time.Time, bool) { return c.until, true }

// ServeDataSource is called only by fixed startup with its own receiver/listener
// owner. Its private jobs have the only production backend-exchange call site.
func (s *InspectorEngineSource) ServeDataSource(n *requestctx.SourceListeners) error {
	if s == nil || s.owner == nil || s.generation == nil || n == nil {
		return ErrInput
	}
	for {
		s.owner.state.mu.Lock()
		stopped := s.owner.state.stopped
		s.owner.state.mu.Unlock()
		if stopped {
			return nil
		}
		select {
		case s.owner.state.dataPrefixes <- struct{}{}:
		default:
			select {
			case <-s.owner.state.dataAvailable:
				continue
			case <-s.owner.state.stoppedSignal:
				return nil
			}
		}
		in, err := s.owner.ReserveInbound()
		if err == ErrCapacity {
			<-s.owner.state.dataPrefixes
			// No accepted application or resource reservation is waiting here.
			// The existing accept actor wakes only on actual capacity release.
			select {
			case <-s.owner.state.dataAvailable:
				continue
			case <-s.owner.state.stoppedSignal:
				return nil
			}
		}
		if err != nil {
			<-s.owner.state.dataPrefixes
			return err
		}
		session, idle, err := n.AcceptDataSource()
		if session == nil {
			<-s.owner.state.dataPrefixes
			_ = in.Close() // Actual Accept returned no endpoint.
			if idle && err == nil {
				continue
			}
			return ErrStopped
		}
		ctx := acceptedDataContext{Context: context.Background(), until: session.DeadlineSource()}
		if err == nil {
			_, err = s.generation.beginOwned(ctx, in, nil, 0, nil, session, true)
		}
		if err == nil {
			continue
		}
		<-s.owner.state.dataPrefixes
		closeErr := session.CloseDataSource()
		certain, _ := session.CleanupDataSource()
		if closeErr == nil && certain {
			_ = in.Close()
		} else {
			s.owner.state.mu.Lock()
			s.failedData = session
			s.failedInbound = in // Retain uncertain pre-job ownership.
			s.owner.state.audit.prejob = true
			s.owner.state.mu.Unlock()
			s.StopSource()
			return ErrStopped
		}
		// Saturation has no queue or extra worker. A known closed connection can
		// be refused while existing jobs keep their unchanged reservations.
		if err != ErrCapacity {
			return err
		}
	}
}
