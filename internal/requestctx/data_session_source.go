//go:build aegvium_transport_source

// SPDX-License-Identifier: BSD-3-Clause
package requestctx

import (
	"context"
	"crypto/tls"
	"net"
	"slices"
	"sync"
	"time"
)

// DataSessionSource is created only by actual fixed-listener Accept, never by
// supplied DTO/Peer/state. It stays private to ONE bodyowner job; no detached
// result can forward, reopen, transfer or retry its backend attempt.
type DataSessionSource struct {
	mu                                                       sync.Mutex
	owner                                                    *pairReceiver
	backends                                                 *backendSet
	inbound, outbound                                        *dataConn
	conn                                                     *tls.Conn
	accepted                                                 time.Time
	readClaimed, complete, authenticated, attempted, dialing bool
	closing, closeClaimed, unsafe, responseStarted           bool
	record                                                   Record
}

type dataConn struct {
	owner                              *DataSessionSource
	raw                                net.Conn
	active                             int // owner.mu
	closeTried, closeReturned, closeOK bool
}

func (s *DataSessionSource) poison() {
	s.mu.Lock()
	s.unsafe = true
	s.closing = true
	s.mu.Unlock()
	if s.owner != nil {
		s.owner.owner.retire()
	}
}
func (e *dataConn) begin() bool {
	s := e.owner
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.unsafe || s.closing || e.closeTried || e.raw == nil {
		return false
	}
	e.active++
	return true
}
func (e *dataConn) end(unsafe bool) {
	s := e.owner
	s.mu.Lock()
	e.active--
	s.mu.Unlock()
	if unsafe {
		s.poison()
	}
}
func (e *dataConn) Read(p []byte) (n int, err error) {
	if !e.begin() {
		return 0, errPair
	}
	returned := false
	defer func() {
		if !returned {
			_ = recover()
			n = 0
			err = errPair
		}
		e.end(!returned)
	}()
	n, err = e.raw.Read(p)
	returned = true
	if n < 0 || n > len(p) {
		n = 0
		err = errPair
		returned = false
	}
	return
}
func (e *dataConn) Write(p []byte) (n int, err error) {
	if !e.begin() {
		return 0, errPair
	}
	returned := false
	defer func() {
		if !returned {
			_ = recover()
			n = 0
			err = errPair
		}
		e.end(!returned)
	}()
	n, err = e.raw.Write(p)
	returned = true
	if n < 0 || n > len(p) {
		n = 0
		err = errPair
		returned = false
	}
	return
}
func (e *dataConn) Close() (err error) {
	s := e.owner
	s.mu.Lock()
	if e.closeTried || s.unsafe || e.raw == nil {
		ok := e.closeReturned && e.closeOK && !s.unsafe
		s.mu.Unlock()
		if ok {
			return nil
		}
		return errPair
	}
	e.closeTried = true
	s.mu.Unlock()
	returned := false
	defer func() {
		if !returned {
			_ = recover()
			err = errPair
		}
		s.mu.Lock()
		e.closeReturned = returned
		e.closeOK = returned && err == nil
		s.mu.Unlock()
		if !returned {
			s.poison()
		}
	}()
	err = e.raw.Close()
	returned = true
	return
}
func (e *dataConn) SetDeadline(t time.Time) (err error) {
	if !e.begin() {
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
	end := e.owner.DeadlineSource()
	if t.IsZero() || t.After(end) {
		t = end
	}
	err = e.raw.SetDeadline(t)
	returned = true
	return
}
func (e *dataConn) SetReadDeadline(t time.Time) error  { return e.SetDeadline(t) }
func (e *dataConn) SetWriteDeadline(t time.Time) error { return e.SetDeadline(t) }

// TLS uses these only as connection metadata; they never supply public facts.
func (e *dataConn) LocalAddr() net.Addr  { return nil }
func (e *dataConn) RemoteAddr() net.Addr { return nil }

func (s *DataSessionSource) DeadlineSource() time.Time {
	if s == nil {
		return time.Time{}
	}
	return s.accepted.Add(8 * time.Second)
}
func (s *DataSessionSource) guarded(err *error) {
	if recover() != nil {
		s.poison()
		*err = errPair
	}
}

// ReadDataSource owns actual authentication and raw input on the SAME Conn.
// Only the job owning its C02 lease calls this method; no Peer is returned.
func (s *DataSessionSource) ReadDataSource(ctx context.Context) (row Record, err error) {
	if s == nil {
		return row, errPair
	}
	defer s.guarded(&err)
	s.mu.Lock()
	if s.readClaimed || s.owner == nil || s.inbound == nil || s.backends == nil || s.closing || s.unsafe {
		s.mu.Unlock()
		return row, errPair
	}
	s.readClaimed = true
	s.mu.Unlock()
	if ctx == nil || ctx.Err() != nil || !time.Now().Before(s.DeadlineSource()) {
		return row, errPair
	}
	r := s.owner
	r.owner.mu.Lock()
	retired := r.owner.retired
	r.owner.mu.Unlock()
	if retired {
		return row, ErrDataUnavailable
	}
	if _, ok := r.serverValidity(time.Now()); !ok {
		return row, errPair
	}
	handshakeUntil := earlier(s.DeadlineSource(), s.accepted.Add(time.Second))
	if s.inbound.SetDeadline(handshakeUntil) != nil {
		return row, errPair
	}
	c := tls.Server(s.inbound, r.config.Clone())
	s.mu.Lock()
	s.conn = c
	s.mu.Unlock()
	hctx, cancel := context.WithDeadline(ctx, handshakeUntil)
	e := c.HandshakeContext(hctx)
	valid := e == nil && hctx.Err() == nil && time.Now().Before(handshakeUntil)
	cancel()
	role, _, ok := r.frontendRole(c, time.Now())
	if !valid || !ok {
		return row, errPair
	}
	s.mu.Lock()
	s.authenticated = true
	s.mu.Unlock()
	until := earlier(s.DeadlineSource(), s.accepted.Add(2*time.Second))
	if s.inbound.SetDeadline(until) != nil {
		return row, errPair
	}
	header, ok := readDataHeader(ctx, until, c, 5120)
	if !ok {
		if len(header) == 5120 {
			return row, ErrDataHeaderLimit
		}
		return row, ErrDataInput
	}
	in, length, parseErr := parseDataRequestHeaderStatus(header)
	if parseErr != nil {
		return row, parseErr
	}
	in.Body = make([]byte, length)
	if !readDataExact(ctx, until, c, in.Body) {
		return row, errPair
	}
	snapshot := r.owner.snapshot.context
	snapshot.mu.Lock()
	if snapshot.retired || snapshot.profile != "M2-H1/3" || ctx.Err() != nil || !time.Now().Before(until) {
		snapshot.mu.Unlock()
		return row, ErrDataUnavailable
	}
	row, err = snapshot.project(Peer{identity: role}, in)
	snapshot.mu.Unlock()
	if err != nil {
		return Record{}, dataProjectionFailure(err)
	}
	s.mu.Lock()
	s.record = row
	s.complete = true
	s.mu.Unlock()
	row.Fields = slices.Clone(row.Fields)
	row.Body = slices.Clone(row.Body)
	return row, nil
}

func (s *DataSessionSource) current(ctx context.Context) bool {
	if ctx == nil || ctx.Err() != nil || !time.Now().Before(s.DeadlineSource()) {
		return false
	}
	s.mu.Lock()
	ok := !s.closing && !s.unsafe && s.complete
	c := s.conn
	s.mu.Unlock()
	if !ok || c == nil {
		return false
	}
	now := time.Now()
	_, serverOK := s.owner.serverValidity(now)
	_, _, frontOK := s.owner.frontendRole(c, now)
	return serverOK && frontOK && s.backends.clientCurrent(now)
}

// ExchangeDataSource has one production caller: the still-charged bodyowner
// transaction worker after its request phases. This method uses the session's
// private immutable request/route, never a supplied allow record/destination.
func (s *DataSessionSource) ExchangeDataSource(ctx context.Context) (attempted, written bool, err error) {
	if s == nil {
		return false, false, errPair
	}
	defer s.guarded(&err)
	if !s.current(ctx) {
		return false, false, errPair
	}
	snapshot := s.owner.owner.snapshot.context
	snapshot.mu.Lock()
	s.mu.Lock()
	if snapshot.retired || s.attempted || s.closing || s.unsafe || ctx.Err() != nil {
		s.mu.Unlock()
		snapshot.mu.Unlock()
		return false, false, errPair
	}
	route, ok := s.backends.routes[s.record.Route]
	if !ok {
		s.mu.Unlock()
		snapshot.mu.Unlock()
		return false, false, errPair
	}
	s.attempted = true
	s.dialing = true
	record := s.record
	s.mu.Unlock()
	snapshot.mu.Unlock()
	attempted = true // Committed effect boundary; later cancellation cannot undo it.
	until := earlier(s.DeadlineSource(), time.Now().Add(2*time.Second))
	fctx, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	dialUntil := earlier(until, time.Now().Add(time.Second))
	dialer := net.Dialer{Deadline: dialUntil}
	raw, e := dialer.DialContext(fctx, "tcp", route.address.String())
	endpoint, closing := s.adoptDialResult(raw)
	if e != nil || endpoint == nil || closing {
		return attempted, false, errPair
	}
	if endpoint.SetDeadline(dialUntil) != nil {
		return attempted, false, errPair
	}
	upstream := tls.Client(endpoint, route.config.Clone())
	hctx, stop := context.WithDeadline(fctx, dialUntil)
	e = upstream.HandshakeContext(hctx)
	handshakeOK := e == nil && hctx.Err() == nil && time.Now().Before(dialUntil)
	stop()
	if !handshakeOK || !s.current(fctx) {
		return attempted, false, errPair
	}
	if endpoint.SetDeadline(until) != nil || !writePairExact(fctx, until, upstream, publicDataRequest(record)) {
		return attempted, false, errPair
	}
	headerUntil := earlier(until, time.Now().Add(time.Second))
	if endpoint.SetDeadline(headerUntil) != nil {
		return attempted, false, errPair
	}
	header, ok := readDataHeader(fctx, headerUntil, upstream, 4096)
	if !ok {
		return attempted, false, errPair
	}
	length, ok := parseDataResponseHeader(header, record.Method)
	if !ok {
		return attempted, false, errPair
	}
	if endpoint.SetDeadline(until) != nil {
		return attempted, false, errPair
	}
	body := make([]byte, length)
	if !readDataExact(fctx, until, upstream, body) || !s.current(fctx) {
		return attempted, false, errPair
	}
	writeUntil := earlier(s.DeadlineSource(), time.Now().Add(4*time.Second))
	if s.inbound.SetDeadline(writeUntil) != nil {
		return attempted, false, errPair
	}
	s.mu.Lock()
	s.responseStarted = true
	s.mu.Unlock()
	response := append(header, body...)
	if !writePairExact(ctx, writeUntil, s.conn, response) {
		return attempted, false, errPair
	}
	return attempted, true, nil
}

// Own the actual result even if cancellation/Close won while Dial was pending.
// This helper is also tested with intercepted net.Conn values, never real Dial.
func (s *DataSessionSource) adoptDialResult(raw net.Conn) (endpoint *dataConn, closing bool) {
	if raw != nil {
		endpoint = &dataConn{owner: s, raw: raw}
	}
	s.mu.Lock()
	s.outbound = endpoint
	closing = s.closing
	s.mu.Unlock()
	if closing && endpoint != nil {
		_ = endpoint.Close()
	}
	s.mu.Lock()
	s.dialing = false
	s.mu.Unlock()
	return
}

func (s *DataSessionSource) RejectDataSource(ctx context.Context, code int) (err error) {
	if s == nil {
		return errPair
	}
	defer s.guarded(&err)
	s.mu.Lock()
	if s.closing || s.unsafe || !s.authenticated || s.responseStarted || s.conn == nil {
		s.mu.Unlock()
		return errPair
	}
	s.responseStarted = true
	c := s.conn
	s.mu.Unlock()
	until := earlier(s.DeadlineSource(), time.Now().Add(4*time.Second))
	if s.inbound.SetDeadline(until) != nil || !writePairExact(ctx, until, c, dataErrorResponse(code)) {
		return errPair
	}
	return nil
}

// Same raw handles, once. Late dial returns are adopted and closed by that
// dial's existing worker; no timeout, cancellation or nil handle refunds it.
func (s *DataSessionSource) CloseDataSource() (err error) {
	if s == nil {
		return errPair
	}
	defer s.guarded(&err)
	s.mu.Lock()
	if s.closeClaimed {
		s.mu.Unlock()
		return errPair
	}
	s.closeClaimed = true
	s.closing = true
	in, out := s.inbound, s.outbound
	unsafe := s.unsafe
	s.mu.Unlock()
	if unsafe {
		return errPair
	}
	if out != nil && out.Close() != nil {
		err = errPair
	}
	s.mu.Lock()
	unsafe = s.unsafe
	s.mu.Unlock()
	if !unsafe && in != nil && in.Close() != nil {
		err = errPair
	}
	return
}

func (s *DataSessionSource) CleanupDataSource() (certain, unsafe bool) {
	if s == nil {
		return false, true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	closed := func(e *dataConn) bool { return e != nil && e.active == 0 && e.closeReturned && e.closeOK }
	return s.closeClaimed && !s.unsafe && !s.dialing && closed(s.inbound) && (s.outbound == nil || closed(s.outbound)), s.unsafe
}
