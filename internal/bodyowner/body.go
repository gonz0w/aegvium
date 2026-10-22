// SPDX-License-Identifier: BSD-3-Clause
// Package bodyowner owns bounded body Read/Close calls and detached memory-only
// records. It provides no authentication, framing proof, engine or dial path.
package bodyowner

import (
	"context"
	"io"
	"sync"
	"time"

	"github.com/gonz0w/aegvium/internal/capacity"
)

const MaxBody = 4096

var (
	ErrInput       = capacity.ErrInput
	ErrStopped     = capacity.ErrStopped
	ErrRetired     = capacity.ErrRetired
	ErrClosed      = capacity.ErrClosed
	ErrTransferred = capacity.ErrTransferred
	ErrCapacity    = capacity.ErrCapacity
)

// Failure contains no source error text or body bytes.
type Failure string

const (
	None        Failure = "None"
	ReadError   Failure = "ReadError"
	LengthError Failure = "LengthError"
	NoProgress  Failure = "NoProgress"
)

// Record is only bytes read from a supplied body, never permission to inspect or
// forward. Every returned Body is detached from the private recording.
type Record struct {
	Generation string
	Body       []byte
}

type Outcome struct {
	Joined, Recorded, Canceled, Retired, Stopped, CloseFailed bool
	ReadFailure                                               Failure
	Record                                                    Record
	Engine                                                    EngineOutcome
}

// All public values are handles. Copying one aliases its private state.
// Raw capacity owners/leases are never exposed to callers.
type Owner struct{ state *ownerState }
type Generation struct{ state *generationState }
type Inbound struct{ state *inboundState }
type Job struct{ state *jobState }

type ownerState struct {
	mu      sync.Mutex
	slots   *capacity.Owner
	stopped bool
	jobs    map[*jobState]struct{}
	engine  *engineState // Nil in the compatible standalone body owner.
}

type generationState struct {
	owner   *ownerState
	slots   *capacity.Generation
	retired bool
}

type inboundState struct {
	owner *ownerState
	slot  *capacity.Inbound
}

type jobState struct {
	owner          *ownerState
	generation     *generationState
	lease          *capacity.Lease
	source         io.ReadCloser
	declared       int
	deadline       time.Time
	parentDone     <-chan struct{}
	ctx            context.Context // Private stdlib context; no supplied parent/hooks.
	cancel         context.CancelFunc
	readDone, done chan struct{}
	body           []byte
	outcome        Outcome // Mutable only under owner.mu; frozen once Joined.
	input          *engineInput
}

func New() *Owner {
	return &Owner{state: &ownerState{slots: capacity.New(), jobs: make(map[*jobState]struct{})}}
}

func (o *Owner) NewGeneration(token string) (*Generation, error) {
	if o == nil || o.state == nil {
		return nil, ErrInput
	}
	s := o.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.engine != nil && s.engine.generationBound {
		return nil, ErrRetired // One startup-bound generation; never reset/replaced.
	}
	g, err := s.slots.NewGeneration(token)
	if err != nil {
		return nil, err
	}
	if s.engine != nil {
		s.engine.generationBound = true
	}
	return &Generation{state: &generationState{owner: s, slots: g}}, nil
}

func (o *Owner) ReserveInbound() (*Inbound, error) {
	if o == nil || o.state == nil {
		return nil, ErrInput
	}
	s := o.state
	s.mu.Lock()
	defer s.mu.Unlock()
	in, err := s.slots.ReserveInbound()
	if err != nil {
		return nil, err
	}
	return &Inbound{state: &inboundState{owner: s, slot: in}}, nil
}

func (in *Inbound) Close() error {
	if in == nil || in.state == nil {
		return ErrInput
	}
	return in.state.slot.Close()
}

func (o *Owner) Usage() capacity.Usage {
	if o == nil || o.state == nil {
		return capacity.Usage{}
	}
	return o.state.slots.Usage()
}

// Begin transfers source only on success. The original receiver deadline and
// cancellation channel are observed without invoking caller methods under locks.
func (g *Generation) Begin(ctx context.Context, in *Inbound, source io.ReadCloser, declaredLength int) (*Job, error) {
	return g.begin(ctx, in, source, declaredLength, nil)
}

func (g *Generation) begin(ctx context.Context, in *Inbound, source io.ReadCloser, declaredLength int, input *engineInput) (*Job, error) {
	if g == nil || g.state == nil || in == nil || in.state == nil || in.state.owner != g.state.owner || ctx == nil || source == nil || declaredLength < 0 || declaredLength > MaxBody {
		return nil, ErrInput
	}
	deadline, bounded := ctx.Deadline()
	if !bounded {
		return nil, ErrInput
	}
	parentDone, parentErr := ctx.Done(), ctx.Err()
	private, cancel := context.WithDeadline(context.Background(), deadline)
	gen, s := g.state, g.state.owner
	s.mu.Lock()
	var err error
	switch {
	case (s.engine == nil) != (input == nil):
		err = ErrInput // Engine jobs cannot escape through the standalone API.
	case s.engine != nil && s.engine.policy != nil && input.policyPin != s.engine.policy.pin:
		err = ErrInput // Equality binds data to this profile; it authenticates no peer.
	case s.stopped:
		err = ErrStopped
	case gen.retired:
		err = ErrRetired
	case !time.Now().Before(deadline):
		err = context.DeadlineExceeded
	case parentErr != nil:
		err = parentErr
	case signaled(parentDone):
		err = context.Canceled
	}
	var lease *capacity.Lease
	if err == nil {
		lease, err = gen.slots.TryRequest(in.state.slot)
	}
	if err != nil {
		s.mu.Unlock()
		cancel()
		return nil, err
	}
	j := &jobState{owner: s, generation: gen, lease: lease, source: source,
		declared: declaredLength, deadline: deadline, parentDone: parentDone,
		ctx: private, cancel: cancel, readDone: make(chan struct{}), done: make(chan struct{}),
		input: input, outcome: Outcome{ReadFailure: None}}
	if input != nil {
		j.outcome.Engine.RequestID = input.id
		j.outcome.Engine.Generation = lease.Generation()
		j.outcome.Engine.BackendEffect = "NoBackendAttempt"
		if policy := s.engine.policy; policy != nil {
			j.outcome.Engine.PolicyPin = policy.pin
			j.outcome.Engine.IntendedMode = "OnUnqualified"
			j.outcome.Engine.RuleCount = policy.ruleCount
		}
	}
	s.jobs[j] = struct{}{}
	s.mu.Unlock()
	go j.read()
	go j.close()
	return &Job{state: j}, nil
}

func signaled(done <-chan struct{}) bool {
	select {
	case <-done:
		return true
	default:
		return false
	}
}

func (j *jobState) canceled() bool {
	return signaled(j.parentDone) || !time.Now().Before(j.deadline) || j.ctx.Err() != nil
}

func (j *jobState) read() {
	buffer := make([]byte, MaxBody+1)
	total, empty := 0, 0
	failure := None
	for {
		if j.canceled() {
			break
		}
		n, err := j.source.Read(buffer[total:])
		if n < 0 || n > len(buffer)-total {
			failure = ReadError
			break
		}
		total += n
		if err != nil && err != io.EOF {
			failure = ReadError
			break
		}
		if total > MaxBody || err == io.EOF && total != j.declared {
			failure = LengthError
			break
		}
		if err == io.EOF {
			break
		}
		if n == 0 {
			empty++
			if empty >= 100 {
				failure = NoProgress
				break
			}
		} else {
			empty = 0
		}
	}
	j.owner.mu.Lock()
	j.outcome.ReadFailure = failure
	j.body = buffer[:total:total]
	j.owner.mu.Unlock()
	close(j.readDone) // No further work by this read worker.
}

func (j *jobState) close() {
	select {
	case <-j.readDone:
	case <-j.parentDone:
		j.cancel()
	case <-j.ctx.Done():
	}
	if err := j.source.Close(); err != nil {
		j.owner.mu.Lock()
		j.outcome.CloseFailed = true
		cancels := j.owner.stopLocked()
		j.owner.mu.Unlock()
		cancelAll(cancels)
	}
	<-j.readDone
	if j.input != nil {
		j.inspect()
	} else {
		j.finish()
	}
	j.cancel() // Release only the private timer; no source I/O/capacity work remains.
}

func (j *jobState) finish() {
	s := j.owner
	s.mu.Lock()
	defer s.mu.Unlock()
	j.outcome.Canceled = j.canceled() || j.generation.retired || s.stopped
	j.outcome.Retired = j.generation.retired
	j.outcome.Stopped = s.stopped
	if !j.outcome.Canceled && j.outcome.ReadFailure == None && !j.outcome.CloseFailed {
		j.outcome.Recorded = true
		j.outcome.Record = Record{Generation: j.lease.Generation(), Body: j.body}
	}
	j.body = nil
	if !j.outcome.CloseFailed {
		j.lease.Close()
		j.source = nil
		delete(s.jobs, j)
	}
	j.outcome.Joined = true
	close(j.done) // No later source I/O or capacity accounting for this job.
}

func (g *Generation) Retire() {
	if g == nil || g.state == nil {
		return
	}
	gen := g.state
	s := gen.owner
	s.mu.Lock()
	gen.retired = true
	gen.slots.Retire()
	if s.engine != nil {
		s.engine.retired = true
	}
	var cancels []context.CancelFunc
	for j := range s.jobs {
		if j.generation == gen {
			cancels = append(cancels, j.cancel)
		}
	}
	s.mu.Unlock()
	cancelAll(cancels)
	s.maybeRetireEngine()
}

// stopLocked marks all jobs unavailable before cancellation is delivered.
func (s *ownerState) stopLocked() []context.CancelFunc {
	s.stopped = true
	s.slots.Stop()
	if s.engine != nil && s.engine.mode == engineActive {
		s.engine.mode = engineCleanupOnly
	}
	cancels := make([]context.CancelFunc, 0, len(s.jobs))
	for j := range s.jobs {
		cancels = append(cancels, j.cancel)
	}
	return cancels
}

func cancelAll(cancels []context.CancelFunc) {
	for _, cancel := range cancels {
		cancel()
	}
}

func (o *Owner) Stop() {
	if o == nil || o.state == nil {
		return
	}
	s := o.state
	s.mu.Lock()
	cancels := s.stopLocked()
	s.mu.Unlock()
	cancelAll(cancels)
}

func (j *Job) Outcome() Outcome {
	if j == nil || j.state == nil {
		return Outcome{ReadFailure: None}
	}
	s := j.state
	s.owner.mu.Lock()
	defer s.owner.mu.Unlock()
	out := s.outcome
	if !out.Joined {
		out.Canceled = s.canceled() || s.generation.retired || s.owner.stopped
		out.Retired, out.Stopped = s.generation.retired, s.owner.stopped
	}
	out.Record.Body = append([]byte(nil), out.Record.Body...)
	return out
}

// Wait cancels only observation, never the capture. It creates no worker.
func (j *Job) Wait(ctx context.Context) (Outcome, error) {
	if j == nil || j.state == nil || ctx == nil {
		return Outcome{ReadFailure: None}, ErrInput
	}
	if signaled(j.state.done) {
		return j.Outcome(), nil
	}
	select {
	case <-j.state.done:
		return j.Outcome(), nil
	case <-ctx.Done():
		out := j.Outcome()
		if out.Joined {
			return out, nil
		}
		return out, ctx.Err()
	}
}
