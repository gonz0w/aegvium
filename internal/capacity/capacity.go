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
type Owner struct {
	mu          sync.Mutex
	initialized bool
	stopped     bool
	usage       Usage
}

type Generation struct {
	owner   *Owner
	token   string
	retired bool
	pending int
}

// Inbound charges a slot before a future accept/handshake. It is not a socket.
// Once transferred, only the request lease can release its slot.
type Inbound struct {
	owner               *Owner
	closed, transferred bool
}

// Lease owns one request and two socket slots. It has no attempt operation or
// allow capability. Actual resource closure/join must precede a future release.
type Lease struct {
	owner      *Owner
	generation *Generation
	inbound    *Inbound
	closed     bool
}

func New() *Owner { return &Owner{initialized: true} }

func (o *Owner) available() bool { return o != nil && o.initialized }

func (o *Owner) NewGeneration(token string) (*Generation, error) {
	if !o.available() || !generationToken(token) {
		return nil, ErrInput
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.stopped {
		return nil, ErrStopped
	}
	return &Generation{owner: o, token: strings.Clone(token)}, nil
}

func (o *Owner) ReserveInbound() (*Inbound, error) {
	if !o.available() {
		return nil, ErrInput
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.stopped {
		return nil, ErrStopped
	}
	if o.usage.Sockets >= MaxSockets {
		return nil, ErrCapacity
	}
	o.usage.Sockets++
	return &Inbound{owner: o}, nil
}

func (g *Generation) TryRequest(in *Inbound) (*Lease, error) {
	if g == nil || !g.owner.available() || in == nil || in.owner != g.owner {
		return nil, ErrInput
	}
	o := g.owner
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.stopped {
		return nil, ErrStopped
	}
	if g.retired {
		return nil, ErrRetired
	}
	if in.closed {
		return nil, ErrClosed
	}
	if in.transferred {
		return nil, ErrTransferred
	}
	if o.usage.Requests >= MaxRequests || o.usage.Sockets >= MaxSockets {
		return nil, ErrCapacity
	}
	in.transferred = true
	o.usage.Requests++
	o.usage.Sockets++ // Reserved outbound slot, private to the lease.
	g.pending++
	return &Lease{owner: o, generation: g, inbound: in}, nil
}

func (in *Inbound) Close() error {
	if in == nil || !in.owner.available() {
		return ErrInput
	}
	o := in.owner
	o.mu.Lock()
	defer o.mu.Unlock()
	if in.closed {
		return nil
	}
	if in.transferred {
		return ErrTransferred
	}
	in.closed = true
	o.usage.Sockets--
	return nil
}

func (l *Lease) Close() {
	if l == nil || !l.owner.available() {
		return
	}
	o := l.owner
	o.mu.Lock()
	defer o.mu.Unlock()
	if l.closed {
		return
	}
	l.closed = true
	l.inbound.closed = true
	o.usage.Requests--
	o.usage.Sockets -= 2
	l.generation.pending--
}

func (g *Generation) Retire() {
	if g == nil || !g.owner.available() {
		return
	}
	g.owner.mu.Lock()
	g.retired = true
	g.owner.mu.Unlock()
}

func (o *Owner) Stop() {
	if !o.available() {
		return
	}
	o.mu.Lock()
	o.stopped = true
	o.mu.Unlock()
}

func (o *Owner) Usage() Usage {
	if !o.available() {
		return Usage{}
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.usage
}

func (g *Generation) Pending() int {
	if g == nil || !g.owner.available() {
		return 0
	}
	g.owner.mu.Lock()
	defer g.owner.mu.Unlock()
	return g.pending
}

func (l *Lease) Generation() string {
	if l == nil || !l.owner.available() {
		return ""
	}
	return l.generation.token
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
