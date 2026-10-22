// SPDX-License-Identifier: BSD-3-Clause
package bodyowner

import (
	"context"
	"io"
	"sync"

	"github.com/corazawaf/coraza/v3/collection"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/types"
)

// EngineOutcome is inert lifecycle evidence. InspectionComplete is deliberately
// never set by this slice: the effective policy/writer profile is unqualified.
// WorkersDone does not imply CleanupCertain, OS resources joined or shutdown.
type EngineOutcome struct {
	WorkersDone, CleanupCertain, Released, InspectionComplete     bool
	CloseStarted, CloseReturned, Uncertain                        bool
	PhasesReturned                                                bool
	Fault                                                         EngineFailure
	RequestID, Generation, PolicyPin, IntendedMode, BackendEffect string
	RuleCount                                                     uint32
}

type EngineFailure string

const (
	EngineNone      EngineFailure = ""
	EngineBusy      EngineFailure = "EngineBusy"
	EngineProfile   EngineFailure = "EngineProfile"
	EngineRejected  EngineFailure = "EngineRejected"
	EnginePhase     EngineFailure = "EnginePhase"
	EngineClose     EngineFailure = "EngineClose"
	EngineUnsafe    EngineFailure = "EngineUnsafe"
	EngineBodyClose EngineFailure = "EngineBodyClose"
)

// Exact pinned API, not a generic closer-shaped engine. The untagged constructor
// remains private; no default factory exists. Source startup binds factory/closer to
// the same exclusively owned prepared WAF once; native admission is absent.
type transactionFactory interface {
	NewTransactionWithID(string) types.Transaction
}

type transactionState interface {
	Variables() plugintypes.TransactionVariables
	LastPhase() types.RulePhase
}

type engineMode uint8

const (
	engineActive engineMode = iota
	engineCleanupOnly
	engineUnsafe
)

type engineState struct {
	gate                                                       sync.Mutex
	factory                                                    transactionFactory
	closer                                                     io.Closer
	mode                                                       engineMode // owner.mu
	generationBound, retired, cacheCloseStarted, cacheReleased bool
	cacheUncertain                                             bool
	references                                                 int
	cacheDone                                                  chan struct{}
	policy                                                     *ownedPolicy
}

func newEngineOwner(factory transactionFactory, closer io.Closer) (*Owner, error) {
	if factory == nil || closer == nil {
		return nil, ErrInput
	}
	o := New()
	o.state.engine = &engineState{factory: factory, closer: closer, cacheDone: make(chan struct{})}
	return o, nil
}

func (g *Generation) beginInspection(ctx context.Context, in *Inbound, source io.ReadCloser, length int, input engineInput) (*Job, error) {
	copyInput, err := copyEngineInput(input, length)
	if err != nil {
		return nil, err
	}
	return g.begin(ctx, in, source, length, copyInput)
}

// invoke catches only a returned stack unwind, never claims cancellation or
// resource cleanup. Neither panic values nor engine errors leave this owner.
func invoke(call func()) (panicked bool) {
	panicked = true
	defer func() { _ = recover() }()
	call()
	return false
}

func (j *jobState) eligibleLocked() bool {
	return !j.canceled() && !j.generation.retired && !j.owner.stopped && j.owner.engine.mode == engineActive && j.outcome.Engine.Fault == EngineNone
}

func (j *jobState) unsafeLocked() []context.CancelFunc {
	j.outcome.Engine.Fault = EngineUnsafe
	j.outcome.Engine.Uncertain = true
	j.owner.engine.mode = engineUnsafe
	return j.owner.stopLocked()
}

// Every engine method, including a state/collection getter, has its own start
// barrier. No batching expands an earlier commitment past cancellation/poison.
func (j *jobState) engineCall(phase bool, call func() EngineFailure) bool {
	s := j.owner
	s.mu.Lock()
	allowed := j.eligibleLocked()
	s.mu.Unlock()
	if !allowed {
		return false
	}
	var fault EngineFailure
	panicked := invoke(func() { fault = call() })
	s.mu.Lock()
	var cancels []context.CancelFunc
	if panicked {
		cancels = j.unsafeLocked()
	} else {
		if phase {
			j.outcome.Engine.PhasesReturned = true
		}
		if fault != EngineNone {
			j.outcome.Engine.Fault = fault
		}
	}
	s.mu.Unlock()
	cancelAll(cancels)
	return !panicked && fault == EngineNone
}

func (j *jobState) inspect() {
	s, e := j.owner, j.owner.engine
	var tx types.Transaction
	s.mu.Lock()
	if j.outcome.CloseFailed {
		j.outcome.Engine.Fault, j.outcome.Engine.Uncertain = EngineBodyClose, true
	}
	eligible := j.eligibleLocked() && j.outcome.ReadFailure == None
	s.mu.Unlock()
	if eligible {
		if !e.gate.TryLock() {
			s.mu.Lock()
			j.outcome.Engine.Fault = EngineBusy
			s.mu.Unlock()
		} else {
			s.mu.Lock()
			create := j.eligibleLocked()
			if create {
				e.references++ // Outstanding before the actual factory call.
			}
			s.mu.Unlock()
			if create {
				panicked := invoke(func() { tx = e.factory.NewTransactionWithID(j.input.id) })
				s.mu.Lock()
				var cancels []context.CancelFunc
				if panicked || tx == nil {
					cancels = j.unsafeLocked()
				}
				s.mu.Unlock()
				e.gate.Unlock() // Poison classification precedes factory-gate release.
				cancelAll(cancels)
			} else {
				e.gate.Unlock()
			}
		}
	}
	if tx != nil {
		j.requestPhases(tx)
		j.logTransaction(tx)
		j.closeTransaction(tx)
		tx = nil // Never inspect/retry the possibly returned-to-pool object.
	}
	j.finishInspection()
}

func (j *jobState) requestPhases(tx types.Transaction) {
	state, ok := tx.(transactionState)
	if !ok {
		j.engineCall(false, func() EngineFailure { return EngineProfile })
		return
	}
	var vars plugintypes.TransactionVariables
	if !j.engineCall(false, func() EngineFailure {
		vars = state.Variables()
		if vars == nil {
			return EngineProfile
		}
		return EngineNone
	}) {
		return
	}
	in := j.input
	calls := []func() EngineFailure{
		func() EngineFailure {
			tx.ProcessConnection(in.client.Addr().String(), int(in.client.Port()), in.server.Addr().String(), int(in.server.Port()))
			return EngineNone
		},
		func() EngineFailure { tx.ProcessURI(in.target, in.method, in.protocol); return EngineNone },
		func() EngineFailure { tx.SetServerName(in.sni); return EngineNone },
	}
	for _, call := range calls {
		if !j.engineCall(false, call) {
			return
		}
	}
	for _, field := range in.fields {
		if !j.engineCall(false, func() EngineFailure { tx.AddRequestHeader(field.Name, field.Value); return EngineNone }) {
			return
		}
	}
	if !j.engineCall(false, func() EngineFailure {
		if tx.IsRuleEngineOff() {
			return EngineProfile
		}
		return EngineNone
	}) || !j.engineCall(false, func() EngineFailure {
		if !tx.IsRequestBodyAccessible() {
			return EngineProfile
		}
		return EngineNone
	}) {
		return
	}
	if !j.engineCall(true, func() EngineFailure {
		if tx.ProcessRequestHeaders() != nil {
			return EngineRejected
		}
		return EngineNone
	}) || !j.checkState(tx, state, vars, types.PhaseRequestHeaders) {
		return
	}
	// A phase can change body access or rule-engine mode. Nil returned errors
	// still do not prove On (DetectionOnly is not exposed by this public API).
	if !j.engineCall(false, func() EngineFailure {
		if tx.IsRuleEngineOff() {
			return EngineProfile
		}
		return EngineNone
	}) || !j.engineCall(false, func() EngineFailure {
		if !tx.IsRequestBodyAccessible() {
			return EngineProfile
		}
		return EngineNone
	}) || !j.engineCall(false, func() EngineFailure {
		interruption, n, err := tx.WriteRequestBody(j.body)
		if interruption != nil {
			return EngineRejected
		}
		if err != nil || n != len(j.body) {
			return EnginePhase
		}
		return EngineNone
	}) || !j.engineCall(true, func() EngineFailure {
		interruption, err := tx.ProcessRequestBody()
		if interruption != nil {
			return EngineRejected
		}
		if err != nil {
			return EnginePhase
		}
		return EngineNone
	}) {
		return
	}
	j.checkState(tx, state, vars, types.PhaseRequestBody)
}

func (j *jobState) checkState(tx types.Transaction, state transactionState, vars plugintypes.TransactionVariables, phase types.RulePhase) bool {
	if !j.engineCall(false, func() EngineFailure {
		if tx.IsInterrupted() {
			return EngineRejected
		}
		return EngineNone
	}) || !j.engineCall(false, func() EngineFailure {
		if state.LastPhase() != phase {
			return EnginePhase
		}
		return EngineNone
	}) {
		return false
	}
	uri, ok := vars.(interface{ URIParseError() collection.Single })
	if !ok {
		j.engineCall(false, func() EngineFailure { return EngineProfile })
		return false
	}
	getters := []func() collection.Single{vars.InboundDataError, vars.RequestBodyError, vars.RequestBodyProcessorError, vars.UrlencodedError, vars.ArgumentsLimitReached, uri.URIParseError}
	for _, get := range getters {
		var value collection.Single
		if !j.engineCall(false, func() EngineFailure {
			value = get()
			if value == nil {
				return EngineProfile
			}
			return EngineNone
		}) || !j.engineCall(false, func() EngineFailure {
			if v := value.Get(); v != "" && v != "0" {
				return EnginePhase
			}
			return EngineNone
		}) {
			return false
		}
	}
	return true
}

func (j *jobState) logTransaction(tx types.Transaction) {
	s := j.owner
	s.mu.Lock()
	allowed := s.engine.mode == engineActive && j.outcome.Engine.PhasesReturned
	s.mu.Unlock()
	if !allowed {
		return
	}
	panicked := invoke(tx.ProcessLogging)
	if panicked {
		s.mu.Lock()
		cancels := j.unsafeLocked()
		s.mu.Unlock()
		cancelAll(cancels)
	}
}

func (j *jobState) closeTransaction(tx types.Transaction) {
	s, e := j.owner, j.owner.engine
	e.gate.Lock() // Existing charged worker; no timeout refund or waiter goroutine.
	s.mu.Lock()
	if e.mode == engineUnsafe {
		j.outcome.Engine.Uncertain = true
		s.mu.Unlock()
		e.gate.Unlock()
		return
	}
	j.outcome.Engine.CloseStarted = true
	s.mu.Unlock()
	var err error
	panicked := invoke(func() { err = tx.Close() })
	s.mu.Lock()
	var cancels []context.CancelFunc
	if panicked {
		cancels = j.unsafeLocked()
	} else {
		j.outcome.Engine.CloseReturned = true
		if err != nil {
			j.outcome.Engine.Fault, j.outcome.Engine.Uncertain = EngineClose, true
			cancels = s.stopLocked()
		} else {
			e.references--
		}
	}
	s.mu.Unlock()
	e.gate.Unlock() // Close-error poison is visible before any later creation.
	cancelAll(cancels)
}

func (j *jobState) finishInspection() {
	s, e := j.owner, j.owner.engine
	s.mu.Lock()
	j.outcome.Canceled = j.canceled() || j.generation.retired || s.stopped
	j.outcome.Retired, j.outcome.Stopped = j.generation.retired, s.stopped
	if e.mode == engineUnsafe {
		j.outcome.Engine.Uncertain = true
		if j.outcome.Engine.Fault == EngineNone {
			j.outcome.Engine.Fault = EngineUnsafe
		}
	}
	j.body, j.input = nil, nil
	j.outcome.Engine.WorkersDone = true
	j.outcome.Engine.CleanupCertain = !j.outcome.CloseFailed && !j.outcome.Engine.Uncertain
	if j.outcome.Engine.CleanupCertain {
		j.lease.Close()
		j.source = nil
		delete(s.jobs, j)
		j.outcome.Engine.Released = true
	}
	// No Record/InspectionComplete path exists, including clean nil-error phases.
	j.outcome.Joined = true
	close(j.done)
	s.mu.Unlock()
	s.maybeRetireEngine()
}

// At most one cache-close worker, only after all owned jobs/references joined.
// A stuck/uncertain job prevents this worker from even being created.
func (s *ownerState) maybeRetireEngine() {
	s.mu.Lock()
	e := s.engine
	if e == nil || !e.retired || len(s.jobs) != 0 || e.references != 0 || e.mode == engineUnsafe || e.cacheCloseStarted {
		s.mu.Unlock()
		return
	}
	e.cacheCloseStarted = true
	s.mu.Unlock()
	go func() {
		e.gate.Lock()
		var err error
		panicked := invoke(func() { err = e.closer.Close() })
		s.mu.Lock()
		e.cacheReleased = !panicked && err == nil
		e.cacheUncertain = !e.cacheReleased
		if panicked {
			e.mode = engineUnsafe
		}
		if e.cacheUncertain {
			_ = s.stopLocked()
		}
		close(e.cacheDone)
		s.mu.Unlock()
		e.gate.Unlock()
	}()
}
