//go:build aegvium_frontend_source

// Adapted from private Vectivium e28959892903225887d855677c307712a59ce071; see LICENSE.Vectivium.
// No public relicensing is made.
package frontendclient

import (
	"net"
	"sync"
	"time"
)

// Only the actual DialContext return enters production. TLS cancellation and the
// match finalizer share this one close attempt; no descriptor getter exists.
type ownedEndpoint struct {
	mu                                   sync.Mutex
	connection                           net.Conn
	active                               int
	closeTried, closeReturned, uncertain bool
	closeError                           error
}

func (e *ownedEndpoint) begin() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.connection == nil || e.closeTried || e.uncertain {
		return false
	}
	e.active++
	return true
}
func (e *ownedEndpoint) end(returned bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.active--
	if !returned || e.active < 0 {
		e.uncertain = true
	}
}
func (e *ownedEndpoint) Read(p []byte) (n int, err error) {
	if !e.begin() {
		return 0, ErrUnavailable
	}
	done := false
	defer func() { e.end(done) }()
	n, err = e.connection.Read(p)
	done = true
	return
}
func (e *ownedEndpoint) Write(p []byte) (n int, err error) {
	if !e.begin() {
		return 0, ErrUnavailable
	}
	done := false
	defer func() { e.end(done) }()
	n, err = e.connection.Write(p)
	done = true
	return
}
func (e *ownedEndpoint) LocalAddr() (out net.Addr) {
	if !e.begin() {
		return nil
	}
	done := false
	defer func() { e.end(done) }()
	out = e.connection.LocalAddr()
	done = true
	return
}
func (e *ownedEndpoint) RemoteAddr() (out net.Addr) {
	if !e.begin() {
		return nil
	}
	done := false
	defer func() { e.end(done) }()
	out = e.connection.RemoteAddr()
	done = true
	return
}
func (e *ownedEndpoint) SetDeadline(t time.Time) (err error) {
	if !e.begin() {
		return ErrUnavailable
	}
	done := false
	defer func() { e.end(done) }()
	err = e.connection.SetDeadline(t)
	done = true
	return
}
func (e *ownedEndpoint) SetReadDeadline(t time.Time) (err error) {
	if !e.begin() {
		return ErrUnavailable
	}
	done := false
	defer func() { e.end(done) }()
	err = e.connection.SetReadDeadline(t)
	done = true
	return
}
func (e *ownedEndpoint) SetWriteDeadline(t time.Time) (err error) {
	if !e.begin() {
		return ErrUnavailable
	}
	done := false
	defer func() { e.end(done) }()
	err = e.connection.SetWriteDeadline(t)
	done = true
	return
}
func (e *ownedEndpoint) Close() (err error) {
	e.mu.Lock()
	if e.closeTried || e.connection == nil {
		e.mu.Unlock()
		return ErrUnavailable
	}
	e.closeTried = true
	e.mu.Unlock()
	done := false
	defer func() {
		if !done {
			_ = recover()
			e.mu.Lock()
			e.uncertain = true
			e.mu.Unlock()
			err = ErrUnavailable
		}
	}()
	err = e.connection.Close()
	e.mu.Lock()
	e.closeReturned = true
	e.closeError = err
	if err != nil {
		e.uncertain = true
	}
	e.mu.Unlock()
	done = true
	return
}
func (e *ownedEndpoint) finalize() bool {
	e.mu.Lock()
	attempt := !e.closeTried
	e.mu.Unlock()
	if attempt {
		_ = e.Close()
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.active != 0 || !e.closeReturned {
		e.uncertain = true
	}
	return e.closeTried && e.closeReturned && e.closeError == nil && e.active == 0 && !e.uncertain
}
