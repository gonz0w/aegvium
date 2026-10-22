//go:build openbsd && aegvium_transport_source

// SPDX-License-Identifier: BSD-3-Clause
package requestctx

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"
)

// SourceListeners owns the two fixed inherited-descriptor destinations. No
// public constructor accepts a listener, address, provider or qualification bit.
type SourceListeners struct {
	mu                      sync.Mutex
	owner                   *InspectorSource
	control, data           *net.TCPListener
	stopped, uncertain      bool
	controlClose, dataClose bool
}

// This gate cannot be enabled by flags/configuration/AGCHECK. Native admission
// must be independently accepted before a later reviewed source change opens it.
func SourceNetworkQualified() bool { return false }

func (s *InspectorSource) PrepareNetworkSource() (*SourceListeners, error) {
	if !SourceNetworkQualified() || s == nil {
		return nil, errPair
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.networkClaimed {
		return nil, errPair
	}
	s.networkClaimed = true
	if !s.prepared || s.uncertain || s.receiver == nil || s.backends == nil || s.bootstrap.snapshot.dataPort == 0 {
		return nil, errPair
	}
	n := &SourceListeners{owner: s}
	s.network = n
	p := s.bootstrap.snapshot
	open := func(ip string, port uint16) (*net.TCPListener, error) {
		addr, e := netip.ParseAddr(ip)
		if e != nil || port == 0 {
			return nil, errPair
		}
		return net.ListenTCP("tcp", net.TCPAddrFromAddrPort(netip.AddrPortFrom(addr, port)))
	}
	var err error
	n.control, err = open(p.address, p.port)
	if err != nil {
		n.uncertain = true
		return n, errPair
	}
	n.data, err = open(p.dataAddress, p.dataPort)
	if err != nil {
		n.uncertain = true
		return n, errPair
	}
	return n, nil
}

func (n *SourceListeners) AcceptDataSource() (*DataSessionSource, bool, error) {
	if n == nil || n.owner == nil {
		return nil, false, errPair
	}
	n.mu.Lock()
	stopped := n.stopped || n.uncertain
	listener := n.data
	n.mu.Unlock()
	if stopped || listener == nil {
		return nil, false, errPair
	}
	n.owner.receiver.owner.mu.Lock()
	retired := n.owner.receiver.owner.retired
	n.owner.receiver.owner.mu.Unlock()
	if retired {
		return nil, false, errPair
	}
	if listener.SetDeadline(time.Now().Add(time.Second)) != nil {
		return nil, false, errPair
	}
	c, err := listener.AcceptTCP()
	if c == nil {
		if e, ok := err.(net.Error); ok && e.Timeout() {
			return nil, true, nil
		}
		return nil, false, errPair
	}
	s := &DataSessionSource{owner: n.owner.receiver, backends: n.owner.backends, accepted: time.Now()}
	s.inbound = &dataConn{owner: s, raw: c}
	if err != nil {
		s.poison()
		return s, false, errPair
	}
	return s, false, nil
}

// No unbound-control refund API is exported. This is called only after the
// actual AcceptTCP returned NO connection, never for a timeout on owned I/O.
func (r *pairReservation) noAcceptedControl() {
	s := r.state
	s.owner.mu.Lock()
	defer s.owner.mu.Unlock()
	if !s.claimed && !s.released {
		s.claimed = true
		s.done = true
		s.released = true
		s.owner.seats--
	}
}

func (n *SourceListeners) ServeControlSource() error {
	if n == nil || n.owner == nil || n.control == nil {
		return errPair
	}
	for {
		n.mu.Lock()
		stopped := n.stopped || n.uncertain
		n.mu.Unlock()
		if stopped {
			return nil
		}
		r, err := n.owner.receiver.reserve(context.Background())
		if err != nil {
			return errPair
		}
		if n.control.SetDeadline(time.Now().Add(time.Second)) != nil {
			r.noAcceptedControl()
			return errPair
		}
		c, err := n.control.AcceptTCP()
		if c == nil {
			r.noAcceptedControl()
			if e, ok := err.(net.Error); ok && e.Timeout() {
				continue
			}
			return errPair
		}
		// A reservation begins before Accept; its original2s parent is never
		// restarted after the kernel wait or the TLS handshake.
		out := n.owner.receiver.serve(r, c)
		if err != nil || out.Retained {
			return errPair
		}
	}
}

func (n *SourceListeners) StopSource() (err error) {
	if n == nil {
		return errPair
	}
	n.mu.Lock()
	n.stopped = true
	if n.uncertain {
		err = errPair
	}
	control, data := n.control, n.data
	closeControl := control != nil && !n.controlClose
	closeData := data != nil && !n.dataClose
	if closeControl {
		n.controlClose = true
	}
	if closeData {
		n.dataClose = true
	}
	n.mu.Unlock()
	n.owner.receiver.owner.retire() // Blocks DATA attempt barrier before Close.
	if closeControl && control.Close() != nil {
		err = errPair
	}
	if closeData && data.Close() != nil {
		err = errPair
	}
	if err != nil {
		n.mu.Lock()
		n.uncertain = true
		n.mu.Unlock()
	}
	return
}
