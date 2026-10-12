// SPDX-License-Identifier: BSD-3-Clause
package spike

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

type proxyOffer struct {
	connection *proxyV1Conn
	accepted   chan struct{}
}

type proxyV1Listener struct {
	net.Listener
	expected netip.AddrPort
	budget   time.Duration
	engine   *atomic.Bool
	ready    chan proxyOffer
	done     chan struct{}
	mu       sync.Mutex
	closed   bool
	owned    map[net.Conn]bool
	stop     sync.Once
	workers  sync.WaitGroup
}

// On validation error the supplied listener stays caller-owned.
func newProxyV1Listener(base net.Listener, expected netip.AddrPort, budget time.Duration, count int, engine *atomic.Bool) (*proxyV1Listener, error) {
	if base == nil || !expected.IsValid() || !expected.Addr().Is4() || expected.Port() == 0 || budget <= 0 || budget > 3*time.Second || count < 1 || count > 16 || engine == nil {
		return nil, errors.New("invalid PROXY listener profile")
	}
	l := &proxyV1Listener{Listener: base, expected: expected, budget: budget, engine: engine, ready: make(chan proxyOffer), done: make(chan struct{}), owned: make(map[net.Conn]bool)}
	l.workers.Add(count)
	for i := 0; i < count; i++ {
		go l.run()
	}
	return l, nil
}

func (l *proxyV1Listener) Ready() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return !l.closed && l.engine.Load()
}

func (l *proxyV1Listener) run() {
	defer l.workers.Done()
	for {
		connection, err := l.Listener.Accept()
		if err != nil || connection == nil {
			l.shutdown()
			return
		}
		l.mu.Lock()
		if l.closed {
			l.mu.Unlock()
			_ = connection.Close()
			return
		}
		l.owned[connection] = false
		l.mu.Unlock()
		prepared, err := prepareProxyV1(connection, l.expected, l.budget)
		if err == nil && l.engine.Load() {
			l.mu.Lock()
			if !l.closed {
				l.owned[connection] = true
			}
			l.mu.Unlock()
			offer := proxyOffer{connection: prepared, accepted: make(chan struct{})}
			select {
			case l.ready <- offer:
				select {
				case <-offer.accepted:
				case <-l.done:
				}
			case <-l.done:
			}
		}
		l.mu.Lock()
		_, held := l.owned[connection]
		delete(l.owned, connection)
		closed := l.closed
		l.mu.Unlock()
		if held {
			_ = connection.Close()
		}
		if closed {
			return
		}
	}
}

func (l *proxyV1Listener) Accept() (net.Conn, error) {
	for {
		select {
		case <-l.done:
			return nil, net.ErrClosed
		case offer := <-l.ready:
			prepared := offer.connection
			l.mu.Lock()
			closed := l.closed
			allowed := !closed && l.engine.Load()
			delete(l.owned, prepared.Conn)
			close(offer.accepted)
			l.mu.Unlock()
			if allowed {
				return prepared, nil
			}
			_ = prepared.Close()
			if closed {
				return nil, net.ErrClosed
			}
		}
	}
}

func (l *proxyV1Listener) shutdown() {
	l.stop.Do(func() {
		l.mu.Lock()
		l.closed = true
		close(l.done)
		connections := make([]net.Conn, 0, len(l.owned))
		for connection := range l.owned {
			connections = append(connections, connection)
		}
		l.mu.Unlock()
		_ = l.Listener.Close()
		for _, connection := range connections {
			_ = connection.Close()
		}
	})
}
func (l *proxyV1Listener) Close() error { l.shutdown(); l.workers.Wait(); return nil }
