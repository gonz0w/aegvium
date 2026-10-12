// SPDX-License-Identifier: BSD-3-Clause
package spike

import (
	"errors"
	"io"
	"net"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type syntheticProxyListener struct {
	queue    chan net.Conn
	done     chan struct{}
	once     sync.Once
	accepted atomic.Int32
}

func syntheticProxyBase() *syntheticProxyListener {
	return &syntheticProxyListener{queue: make(chan net.Conn, 8), done: make(chan struct{})}
}
func (s *syntheticProxyListener) Accept() (net.Conn, error) {
	select {
	case <-s.done:
		return nil, net.ErrClosed
	case c := <-s.queue:
		s.accepted.Add(1)
		return c, nil
	}
}
func (s *syntheticProxyListener) Close() error { s.once.Do(func() { close(s.done) }); return nil }
func (s *syntheticProxyListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 18084}
}
func proxyAwait(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("listener condition not reached")
}
func proxyListenerFixture(t *testing.T) (*syntheticProxyListener, *proxyV1Listener, *atomic.Bool) {
	t.Helper()
	base := syntheticProxyBase()
	engine := new(atomic.Bool)
	engine.Store(true)
	listener, err := newProxyV1Listener(base, proxyExpected, 3*time.Second, 2, engine)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return base, listener, engine
}
func proxyOfferPipe(t *testing.T, base *syntheticProxyListener) net.Conn {
	t.Helper()
	server, client := proxyPipe(t)
	base.queue <- server
	return client
}
func proxyAccept(t *testing.T, listener net.Listener) net.Conn {
	t.Helper()
	type result struct {
		connection net.Conn
		err        error
	}
	done := make(chan result, 1)
	go func() { c, e := listener.Accept(); done <- result{c, e} }()
	select {
	case r := <-done:
		if r.err != nil {
			t.Fatal(r.err)
		}
		t.Cleanup(func() { _ = r.connection.Close() })
		return r.connection
	case <-time.After(3 * time.Second):
		_ = listener.Close()
		r := <-done
		if r.connection != nil {
			_ = r.connection.Close()
		}
		t.Fatal("Accept did not complete")
		return nil
	}
}
func proxySendPrefix(t *testing.T, client net.Conn, body string) <-chan error {
	t.Helper()
	done := make(chan error, 1)
	go func() { _, err := io.WriteString(client, proxyPrefix+body); done <- err }()
	return done
}
func proxyCloseListener(t *testing.T, listener *proxyV1Listener) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- listener.Close() }()
	proxyDone(t, done)
	if listener.Ready() {
		t.Fatal("closed listener ready")
	}
	t.Log("listener-close workers-joined=true ready=false")
}

func TestProxyV1Listener(t *testing.T) {
	t.Run("progress", func(t *testing.T) {
		base, listener, _ := proxyListenerFixture(t)
		slow := proxyOfferPipe(t, base)
		proxyAwait(t, func() bool { return base.accepted.Load() == 1 })
		fast := proxyOfferPipe(t, base)
		done := proxySendPrefix(t, fast, "body")
		accepted := proxyAccept(t, listener)
		got := make([]byte, 4)
		if _, err := io.ReadFull(accepted, got); err != nil || string(got) != "body" {
			t.Fatalf("handoff %q %v", got, err)
		}
		proxyDone(t, done)
		listener.mu.Lock()
		pending := len(listener.owned)
		listener.mu.Unlock()
		if pending != 1 {
			t.Fatal("slow prefix no longer pending during valid handoff")
		}
		proxyCloseListener(t, listener)
		proxyClosed(t, slow)
		// Application ownership survives listener Close; application closes it.
		write := make(chan error, 1)
		go func() { _, err := io.WriteString(fast, "after"); write <- err }()
		got = make([]byte, 5)
		_ = accepted.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := io.ReadFull(accepted, got); err != nil || string(got) != "after" {
			t.Fatalf("application ownership lost: %q %v", got, err)
		}
		proxyDone(t, write)
		_ = accepted.Close()
		proxyClosed(t, fast)
	})
	t.Run("capacity", func(t *testing.T) {
		base, listener, engine := proxyListenerFixture(t)
		for _, count := range []int{0, 17} {
			if c, e := newProxyV1Listener(base, proxyExpected, time.Second, count, engine); c != nil || e == nil {
				t.Fatal("invalid count accepted")
			}
		}
		clients := []net.Conn{proxyOfferPipe(t, base), proxyOfferPipe(t, base), proxyOfferPipe(t, base)}
		proxyAwait(t, func() bool { return base.accepted.Load() == 2 })
		time.Sleep(30 * time.Millisecond)
		if base.accepted.Load() != 2 {
			t.Fatal("accepted beyond worker limit")
		}
		listener.mu.Lock()
		owned := len(listener.owned)
		listener.mu.Unlock()
		if owned != 2 {
			t.Fatalf("owned=%d", owned)
		}
		t.Log("listener-capacity accepted=2 owned=2 limit=2")
		proxyCloseListener(t, listener)
		proxyClosed(t, clients[0])
		proxyClosed(t, clients[1])
		// Synthetic queue is caller-owned, unlike kernel backlog; cleanup its entry.
		select {
		case queued := <-base.queue:
			_ = queued.Close()
		default:
			t.Fatal("third connection escaped bound")
		}
		proxyClosed(t, clients[2])
	})
	t.Run("close-pending", func(t *testing.T) {
		base, listener, _ := proxyListenerFixture(t)
		client := proxyOfferPipe(t, base)
		proxyAwait(t, func() bool { return base.accepted.Load() == 1 })
		done := make(chan error, 1)
		go func() {
			c, e := listener.Accept()
			if c != nil {
				_ = c.Close()
				done <- errors.New("closed Accept returned connection")
				return
			}
			if !errors.Is(e, net.ErrClosed) {
				done <- e
				return
			}
			done <- nil
		}()
		proxyCloseListener(t, listener)
		proxyDone(t, done)
		proxyClosed(t, client)
	})
	t.Run("close-undelivered", func(t *testing.T) {
		base, listener, _ := proxyListenerFixture(t)
		client := proxyOfferPipe(t, base)
		done := proxySendPrefix(t, client, "")
		proxyDone(t, done)
		proxyAwait(t, func() bool {
			listener.mu.Lock()
			defer listener.mu.Unlock()
			for _, prepared := range listener.owned {
				if prepared {
					return true
				}
			}
			return false
		})
		proxyCloseListener(t, listener)
		proxyClosed(t, client)
	})
	t.Run("engine-gate", func(t *testing.T) {
		base, listener, engine := proxyListenerFixture(t)
		engine.Store(false)
		if listener.Ready() {
			t.Fatal("engine-unready listener ready")
		}
		client := proxyOfferPipe(t, base)
		done := proxySendPrefix(t, client, "")
		proxyDone(t, done)
		proxyClosed(t, client)
		engine.Store(true)
		if !listener.Ready() {
			t.Fatal("engine recovery not ready")
		}
		queued := proxyOfferPipe(t, base)
		write := proxySendPrefix(t, queued, "")
		proxyDone(t, write)
		proxyAwait(t, func() bool {
			listener.mu.Lock()
			defer listener.mu.Unlock()
			for _, prepared := range listener.owned {
				if prepared {
					return true
				}
			}
			return false
		})
		engine.Store(false)
		handoff := make(chan error, 1)
		go func() {
			c, e := listener.Accept()
			if c != nil {
				_ = c.Close()
			}
			handoff <- e
		}()
		proxyClosed(t, queued)
		select {
		case <-handoff:
			t.Fatal("engine-unready offer reached application")
		default:
		}
		engine.Store(true)
		next := proxyOfferPipe(t, base)
		write = proxySendPrefix(t, next, "")
		proxyDone(t, handoff)
		proxyDone(t, write)
		proxyClosed(t, next)

	})
	t.Run("accept-failure", func(t *testing.T) {
		base, listener, _ := proxyListenerFixture(t)
		_ = base.Close()
		proxyAwait(t, func() bool { return !listener.Ready() })
		proxyCloseListener(t, listener)
		if c, e := listener.Accept(); c != nil || !errors.Is(e, net.ErrClosed) {
			t.Fatalf("closed Accept %v %v", c, e)
		}
	})
}

func TestProxyV1ListenerTCP(t *testing.T) {
	if runtime.GOOS != "openbsd" || os.Getenv("AEGVIUM_NATIVE_REPEAT") != "1" {
		t.Skip("owned OpenBSD native repeat only")
	}
	for _, kind := range []string{"progress", "bare-head"} {
		t.Run(kind, func(t *testing.T) {
			base, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			engine := new(atomic.Bool)
			engine.Store(true)
			listener, err := newProxyV1Listener(base, proxyExpected, 3*time.Second, 2, engine)
			if err != nil {
				_ = base.Close()
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = listener.Close() })
			dial := func() net.Conn {
				c, e := net.DialTimeout("tcp4", base.Addr().String(), time.Second)
				if e != nil {
					t.Fatal(e)
				}
				t.Cleanup(func() { _ = c.Close() })
				if e := c.SetDeadline(time.Now().Add(3 * time.Second)); e != nil {
					t.Fatal(e)
				}
				return c
			}
			client := dial()
			if kind == "progress" {
				proxyAwait(t, func() bool { listener.mu.Lock(); defer listener.mu.Unlock(); return len(listener.owned) == 1 })
				fast := dial()
				write := proxySendPrefix(t, fast, "TCP body")
				accepted := proxyAccept(t, listener)
				got := make([]byte, 8)
				if _, e := io.ReadFull(accepted, got); e != nil || string(got) != "TCP body" || accepted.RemoteAddr().String() != fast.LocalAddr().String() {
					t.Fatalf("TCP progress %q %v", got, e)
				}
				proxyDone(t, write)
				listener.mu.Lock()
				pending := len(listener.owned)
				listener.mu.Unlock()
				if pending != 1 {
					t.Fatal("slow TCP prefix no longer pending during handoff")
				}
				_ = accepted.Close()
				proxyClosed(t, fast)
			} else {
				if _, e := io.WriteString(client, "HEAD /_aegvium/ready HTTP/1.1\r\n\r\n"); e != nil {
					t.Fatal(e)
				}
				var b [1]byte
				n, e := client.Read(b[:])
				var timeout net.Error
				if n != 0 || e == nil || (errors.As(e, &timeout) && timeout.Timeout()) {
					t.Fatalf("bare HEAD not rejected: %d %v", n, e)
				}
			}
			proxyCloseListener(t, listener)
			if kind == "progress" {
				proxyClosed(t, client)
			}
			probe, e := net.DialTimeout("tcp4", base.Addr().String(), time.Second)
			if probe != nil {
				_ = probe.Close()
				t.Fatal("closed TCP listener accepted")
			}
			if e == nil {
				t.Fatal("listener absence not proven")
			}
			t.Log("tcp-listener absence=verified")
		})
	}
}
