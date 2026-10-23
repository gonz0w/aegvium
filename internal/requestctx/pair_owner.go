// SPDX-License-Identifier: BSD-3-Clause
package requestctx

import (
	"context"
	"net"
	"sync"
	"time"
)

// Private pre-Accept accounting; copied handles alias state. No listener exists.
type pairControlOwner struct {
	mu       sync.Mutex
	snapshot *pairedSnapshot
	retired  bool
	seats    int
}
type pairReservation struct{ state *pairReservationState }
type pairReservationState struct {
	owner                   *pairControlOwner
	parent                  context.Context
	total                   time.Time
	claimed, done, released bool
	endpoint                *pairEndpoint
}
type pairEndpoint struct {
	reservation                                *pairReservationState
	raw                                        net.Conn
	total                                      time.Time
	active                                     int // owner.mu; ALL actual raw calls must join before release.
	closing, closeReturned, closeOK, uncertain bool
}

func (o *pairControlOwner) reserve(ctx context.Context) (*pairReservation, error) {
	if o == nil || o.snapshot == nil || ctx == nil || ctx.Err() != nil {
		return nil, errPair
	}
	total := time.Now().Add(2 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(total) {
		total = d
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.retired || o.seats >= 2 || !time.Now().Before(total) {
		return nil, errPair
	}
	o.seats++
	return &pairReservation{state: &pairReservationState{owner: o, parent: ctx, total: total}}, nil
}
func (o *pairControlOwner) retire() {
	if o == nil {
		return
	}
	o.mu.Lock()
	o.retired = true
	o.mu.Unlock()
	if o.snapshot != nil {
		o.snapshot.context.Retire()
	}
}
func (r *pairReservation) bind(raw net.Conn) (*pairEndpoint, error) {
	if r == nil || r.state == nil {
		return nil, errPair
	}
	s := r.state
	s.owner.mu.Lock()
	defer s.owner.mu.Unlock()
	if s.claimed {
		return nil, errPair
	}
	s.claimed = true
	if raw == nil {
		return nil, errPair
	} // No nil-as-absence refund/second bind.
	s.endpoint = &pairEndpoint{reservation: s, raw: raw, total: s.total}
	return s.endpoint, nil
}
func (s *pairReservationState) releaseLocked() {
	e := s.endpoint
	if !s.released && s.done && e != nil && e.closeReturned && e.closeOK && !e.uncertain && e.active == 0 {
		s.released = true
		s.owner.seats--
		e.raw = nil
	}
}
func (s *pairReservationState) finish() {
	s.owner.mu.Lock()
	s.done = true
	s.releaseLocked()
	s.owner.mu.Unlock()
}
func (e *pairEndpoint) start() bool {
	o := e.reservation.owner
	o.mu.Lock()
	defer o.mu.Unlock()
	if e.closing || e.uncertain || e.raw == nil {
		return false
	}
	e.active++
	return true
}
func (e *pairEndpoint) end(unsafe bool) {
	o := e.reservation.owner
	o.mu.Lock()
	e.active--
	if unsafe {
		e.uncertain = true
		e.closing = true
		o.retired = true
	}
	e.reservation.releaseLocked()
	o.mu.Unlock()
	if unsafe {
		o.snapshot.context.Retire()
	}
}
func (e *pairEndpoint) Read(p []byte) (n int, err error) {
	if !e.start() {
		return 0, errPair
	}
	returned, unsafe := false, false
	defer func() {
		if !returned {
			_ = recover()
			n = 0
			err = errPair
			unsafe = true
		}
		e.end(unsafe)
	}()
	n, err = e.raw.Read(p)
	returned = true
	if n < 0 || n > len(p) {
		n = 0
		err = errPair
		unsafe = true
	}
	return
}
func (e *pairEndpoint) Write(p []byte) (n int, err error) {
	if !e.start() {
		return 0, errPair
	}
	returned, unsafe := false, false
	defer func() {
		if !returned {
			_ = recover()
			n = 0
			err = errPair
			unsafe = true
		}
		e.end(unsafe)
	}()
	n, err = e.raw.Write(p)
	returned = true
	if n < 0 || n > len(p) {
		n = 0
		err = errPair
		unsafe = true
	}
	return
}
func (e *pairEndpoint) poison() {
	o := e.reservation.owner
	o.mu.Lock()
	e.uncertain = true
	e.closing = true
	o.retired = true
	o.mu.Unlock()
	o.snapshot.context.Retire()
}
func (e *pairEndpoint) Close() (err error) {
	o := e.reservation.owner
	o.mu.Lock()
	if e.closing || e.uncertain || e.raw == nil {
		o.mu.Unlock()
		return errPair
	}
	e.closing = true // TLS internal cancellation and outer cleanup share this claim.
	o.mu.Unlock()
	returned := false
	defer func() {
		if !returned {
			_ = recover()
			err = errPair
		}
		o.mu.Lock()
		e.closeReturned = returned
		e.closeOK = returned && err == nil
		if !e.closeOK {
			e.uncertain = true
			o.retired = true
		}
		e.reservation.releaseLocked()
		o.mu.Unlock()
		if !returned || err != nil {
			o.snapshot.context.Retire()
		}
	}()
	err = e.raw.Close()
	returned = true
	return
}
func (e *pairEndpoint) deadline(t time.Time, which int) (err error) {
	if !e.start() {
		return errPair
	}
	returned := false
	defer func() {
		if !returned {
			_ = recover()
			err = errPair
		}
		e.end(!returned)
	}()
	if t.IsZero() || t.After(e.total) {
		t = e.total
	}
	switch which {
	case 0:
		err = e.raw.SetDeadline(t)
	case 1:
		err = e.raw.SetReadDeadline(t)
	case 2:
		err = e.raw.SetWriteDeadline(t)
	}
	returned = true
	return
}
func (e *pairEndpoint) SetDeadline(t time.Time) error      { return e.deadline(t, 0) }
func (e *pairEndpoint) SetReadDeadline(t time.Time) error  { return e.deadline(t, 1) }
func (e *pairEndpoint) SetWriteDeadline(t time.Time) error { return e.deadline(t, 2) }
func (e *pairEndpoint) address(remote bool) (a net.Addr) {
	if !e.start() {
		return nil
	}
	returned := false
	defer func() {
		if !returned {
			_ = recover()
			a = nil
		}
		e.end(!returned)
	}()
	if remote {
		a = e.raw.RemoteAddr()
	} else {
		a = e.raw.LocalAddr()
	}
	returned = true
	return
}
func (e *pairEndpoint) LocalAddr() net.Addr  { return e.address(false) }
func (e *pairEndpoint) RemoteAddr() net.Addr { return e.address(true) }
