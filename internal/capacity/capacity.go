// SPDX-License-Identifier: BSD-3-Clause
// Package capacity models inert shared M2-C02 reservations. It opens no socket,
// authenticates no peer and grants no inspection or forwarding permission.
package capacity

import (
	"errors"
	"strings"
	"sync"
)

const (
	MaxRequests = 4
	MaxSockets  = 8
)

var (
	ErrInput       = errors.New("invalid capacity input")
	ErrStopped     = errors.New("capacity owner stopped")
	ErrRetired     = errors.New("capacity generation retired")
	ErrCapacity    = errors.New("capacity reached")
	ErrClosed      = errors.New("capacity reservation closed")
	ErrTransferred = errors.New("capacity reservation transferred")
)

// Usage is an accounting observation, never readiness or permission to apply.
type Usage struct{ Requests, Sockets int }

// Owner shares fixed accounting across generations. A future process owner must
// use one instance and bind reservations to actual resources and their cleanup.
// This model cannot enforce those integration obligations. Its zero value rejects.
// All public handles alias private state when copied, including close/retirement.
type Owner struct{ state *ownerState }

type ownerState struct {
	mu      sync.Mutex
	stopped bool
	usage   Usage
}

type Generation struct{ state *generationState }

type generationState struct {
	owner   *ownerState
	token   string
	retired bool
	pending int
}

// Inbound charges a slot before a future accept/handshake. It is not a socket.
// Once transferred, only the request lease can release its slot.
type Inbound struct{ state *inboundState }

type inboundState struct {
	owner               *ownerState
	closed, transferred bool
}

// Lease owns one request and two socket slots. It has no attempt operation or
// allow capability. Actual resource closure/join must precede a future release.
type Lease struct{ state *leaseState }

type leaseState struct {
	owner      *ownerState
	generation *generationState
	inbound    *inboundState
	closed     bool
}

func New() *Owner { return &Owner{state: &ownerState{}} }

func (o *Owner) available() bool { return o != nil && o.state != nil }

func (o *Owner) NewGeneration(token string) (*Generation, error) {
	if !o.available() || !generationToken(token) {
		return nil, ErrInput
	}
	s := o.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return nil, ErrStopped
	}
	return &Generation{state: &generationState{owner: s, token: strings.Clone(token)}}, nil
}

func (o *Owner) ReserveInbound() (*Inbound, error) {
	if !o.available() {
		return nil, ErrInput
	}
	s := o.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return nil, ErrStopped
	}
	if s.usage.Sockets >= MaxSockets {
		return nil, ErrCapacity
	}
	s.usage.Sockets++
	return &Inbound{state: &inboundState{owner: s}}, nil
}

func (g *Generation) TryRequest(in *Inbound) (*Lease, error) {
	if g == nil || g.state == nil || in == nil || in.state == nil || in.state.owner != g.state.owner {
		return nil, ErrInput
	}
	gen, inbound := g.state, in.state
	o := gen.owner
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.stopped {
		return nil, ErrStopped
	}
	if gen.retired {
		return nil, ErrRetired
	}
	if inbound.closed {
		return nil, ErrClosed
	}
	if inbound.transferred {
		return nil, ErrTransferred
	}
	if o.usage.Requests >= MaxRequests || o.usage.Sockets >= MaxSockets {
		return nil, ErrCapacity
	}
	inbound.transferred = true
	o.usage.Requests++
	o.usage.Sockets++ // Reserved outbound slot, private to the lease.
	gen.pending++
	return &Lease{state: &leaseState{owner: o, generation: gen, inbound: inbound}}, nil
}

func (in *Inbound) Close() error {
	if in == nil || in.state == nil {
		return ErrInput
	}
	s := in.state
	o := s.owner
	o.mu.Lock()
	defer o.mu.Unlock()
	if s.closed {
		return nil
	}
	if s.transferred {
		return ErrTransferred
	}
	s.closed = true
	o.usage.Sockets--
	return nil
}

func (l *Lease) Close() {
	if l == nil || l.state == nil {
		return
	}
	s := l.state
	o := s.owner
	o.mu.Lock()
	defer o.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	s.inbound.closed = true
	o.usage.Requests--
	o.usage.Sockets -= 2
	s.generation.pending--
}

func (g *Generation) Retire() {
	if g == nil || g.state == nil {
		return
	}
	s := g.state
	s.owner.mu.Lock()
	s.retired = true
	s.owner.mu.Unlock()
}

func (o *Owner) Stop() {
	if !o.available() {
		return
	}
	s := o.state
	s.mu.Lock()
	s.stopped = true
	s.mu.Unlock()
}

func (o *Owner) Usage() Usage {
	if !o.available() {
		return Usage{}
	}
	s := o.state
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.usage
}

func (g *Generation) Pending() int {
	if g == nil || g.state == nil {
		return 0
	}
	s := g.state
	s.owner.mu.Lock()
	defer s.owner.mu.Unlock()
	return s.pending
}

func (l *Lease) Generation() string {
	if l == nil || l.state == nil {
		return ""
	}
	return l.state.generation.token
}

func generationToken(s string) bool {
	if len(s) != 32 {
		return false
	}
	for i := range s {
		if !(s[i] >= '0' && s[i] <= '9' || s[i] >= 'a' && s[i] <= 'f') {
			return false
		}
	}
	return true
}
