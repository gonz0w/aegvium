// SPDX-License-Identifier: BSD-3-Clause
package bodyowner

import (
	"context"

	"github.com/gonz0w/aegvium/internal/requestctx"
)

// OS-boundary interface private to this package. The only production value is
// the actual receiver-created requestctx.DataSessionSource. Tests intercept it
// with finite in-memory calls; no public caller can submit a provider/allow DTO.
type dataSession interface {
	ReadDataSource(context.Context) (requestctx.Record, error)
	ExchangeDataSource(context.Context) (bool, bool, error)
	RejectDataSource(context.Context, int) error
	CloseDataSource() error
	CleanupDataSource() (bool, bool)
}

func (j *jobState) readData() {
	var row requestctx.Record
	var err error
	panicked := invoke(func() { row, err = j.data.ReadDataSource(j.ctx) })
	if !panicked && err != nil {
		var unsafe bool
		panicked = invoke(func() { _, unsafe = j.data.CleanupDataSource() }) || unsafe
	}
	s := j.owner
	var input *engineInput
	if !panicked && err == nil {
		input, err = copyEngineInput(engineInput{id: row.RequestID, sni: row.SNI, protocol: row.Protocol, method: row.Method, target: row.Target, policyPin: row.PolicyPin, client: row.Remote, server: row.Local, publicPort: row.PublicPort, fields: row.Fields}, len(row.Body))
		if row.Generation != j.generation.token {
			err = ErrInput
		}
	}
	s.mu.Lock()
	var cancels []context.CancelFunc
	if panicked {
		cancels = j.unsafeLocked()
	} else if err != nil || input == nil || input.policyPin != s.engine.policy.pin {
		j.outcome.ReadFailure = ReadError
		j.dataStatus = 400
		switch err {
		case requestctx.ErrDataHeaderLimit:
			j.dataStatus = 431
		case requestctx.ErrDataBodyLimit:
			j.dataStatus = 413
		case requestctx.ErrDataAuthority:
			j.dataStatus = 421
		case requestctx.ErrDataForbidden:
			j.dataStatus = 403
		case requestctx.ErrDataUnavailable:
			j.dataStatus = 503
		}
	} else {
		j.input = input
		j.body = row.Body
		j.outcome.Engine.RequestID = input.id
		j.outcome.Engine.Generation = j.generation.token
		j.outcome.Engine.PolicyPin = s.engine.policy.pin
		j.outcome.Engine.RuleCount = s.engine.policy.ruleCount
		j.outcome.Engine.IntendedMode = "OnUnqualified"
	}
	j.outcome.Engine.BackendEffect = "NoBackendAttempt"
	s.mu.Unlock()
	cancelAll(cancels)
	if j.prefixOwned {
		<-s.dataPrefixes
		j.prefixOwned = false
		s.wakeData()
	}
	j.inspect() // SAME worker/transaction through exchange and terminal cleanup.
	j.cancel()
}

func (j *jobState) exchangeData() {
	s := j.owner
	s.mu.Lock()
	eligible := j.eligibleLocked() && j.inspected && j.input != nil && s.engine.policy != nil && j.input.policyPin == s.engine.policy.pin
	if eligible {
		j.outcome.Engine.BackendEffect = "PossiblyEffected"
	}
	s.mu.Unlock()
	if !eligible {
		return
	}
	var attempted, written bool
	var err error
	panicked := invoke(func() { attempted, written, err = j.data.ExchangeDataSource(j.ctx) })
	if !panicked && err != nil {
		var unsafe bool
		panicked = invoke(func() { _, unsafe = j.data.CleanupDataSource() }) || unsafe
	}
	s.mu.Lock()
	var cancels []context.CancelFunc
	if panicked || written && (!attempted || err != nil) || err == nil && !written {
		cancels = j.unsafeLocked()
	} else {
		j.outcome.Engine.ExchangeReturned = true
		j.outcome.Engine.ResponseWritten = written
		if !attempted {
			j.outcome.Engine.BackendEffect = "NoBackendAttempt"
		}
		if err != nil {
			j.outcome.Engine.Fault = EnginePhase
		}
	}
	s.mu.Unlock()
	cancelAll(cancels)
}

// Network cleanup JOIN precedes logging/tx.Close. Neither a finished exchange
// nor an observer's cancellation releases the job, source or transaction.
func (j *jobState) joinData() {
	s := j.owner
	s.mu.Lock()
	writeError := s.engine.mode == engineActive && !s.stopped && !j.canceled() && !j.outcome.Engine.ResponseWritten
	code := 503
	if j.outcome.ReadFailure != None {
		code = j.dataStatus
		if code == 0 {
			code = 400
		}
	} else if j.outcome.Engine.BackendEffect == "PossiblyEffected" {
		code = 502
	} else if j.outcome.Engine.Fault == EngineRejected {
		code = 403
	}
	s.mu.Unlock()
	if writeError {
		if invoke(func() { _ = j.data.RejectDataSource(j.ctx, code) }) {
			s.mu.Lock()
			cancels := j.unsafeLocked()
			s.mu.Unlock()
			cancelAll(cancels)
		}
	}
	close(j.readDone) // No later DATA Read/Write/Dial from this worker.
	<-j.dataCleaned
}

func (j *jobState) closeData() {
	select {
	case <-j.readDone:
	case <-j.parentDone:
		j.cancel()
	case <-j.ctx.Done():
	}
	s := j.owner
	s.mu.Lock()
	unsafe := s.engine.mode == engineUnsafe
	s.mu.Unlock()
	var err error
	if !unsafe {
		unsafe = invoke(func() { err = j.data.CloseDataSource() })
	}
	// Even a returned Close cannot release a dial/Read/Write still in progress.
	<-j.readDone
	certain := false
	if !unsafe {
		var transportUnsafe bool
		unsafe = invoke(func() { certain, transportUnsafe = j.data.CleanupDataSource() }) || transportUnsafe
	}
	s.mu.Lock()
	var cancels []context.CancelFunc
	if unsafe {
		cancels = j.unsafeLocked()
	}
	if err != nil || !certain || unsafe {
		j.outcome.CloseFailed = true
		j.outcome.Engine.Uncertain = true
		if !unsafe {
			cancels = s.stopLocked()
		}
	}
	s.mu.Unlock()
	cancelAll(cancels)
	close(j.dataCleaned) // Actual cleanup result, never a timeout/reclamation claim.
}
