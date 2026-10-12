// SPDX-License-Identifier: BSD-3-Clause
package spike

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

var proxyExpected = netip.MustParseAddrPort("127.0.0.1:18084")

func proxyPipe(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	server, client := net.Pipe()
	t.Cleanup(func() { _ = server.Close(); _ = client.Close() })
	if err := client.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return server, client
}

func proxyDone(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("connection task did not complete")
	}
}

func proxyClosed(t *testing.T, client net.Conn) {
	t.Helper()
	// net.Pipe refuses deadline changes once its remote endpoint is closed.
	if err := client.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil && !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal(err)
	}
	var b [1]byte
	if n, err := client.Read(b[:]); n != 0 || err != io.EOF {
		t.Fatalf("peer not closed: n=%d err=%v", n, err)
	}
}

func proxyTimeout(t *testing.T, server net.Conn, client net.Conn) {
	t.Helper()
	started := time.Now()
	connection, err := prepareProxyV1(server, proxyExpected, 100*time.Millisecond)
	var timeout net.Error
	elapsed := time.Since(started)
	if connection != nil || !errors.As(err, &timeout) || !timeout.Timeout() || elapsed > 5*time.Second {
		t.Fatalf("timeout connection=%v err=%v elapsed=%s", connection, err, elapsed)
	}
	proxyClosed(t, client)
	t.Logf("prefix-timeout milliseconds=%d timeout=true closed=true", elapsed.Milliseconds())
}

func TestProxyV1Conn(t *testing.T) {
	t.Run("coalesced", func(t *testing.T) {
		server, client := proxyPipe(t)
		done := make(chan error, 1)
		go func() { _, err := io.WriteString(client, proxyPrefix+"application bytes"); done <- err }()
		connection, err := prepareProxyV1(server, proxyExpected, 3*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len("application bytes"))
		if _, err := io.ReadFull(connection, got); err != nil || string(got) != "application bytes" {
			t.Fatalf("bytes=%q err=%v", got, err)
		}
		if connection.RemoteAddr() != server.RemoteAddr() || connection.identity.source.String() != "192.0.2.10:54321" {
			t.Fatal("transport peer/advertised source conflated")
		}
		proxyDone(t, done)
		_ = connection.Close()
		proxyClosed(t, client)
	})
	t.Run("deadline-cleared", func(t *testing.T) {
		server, client := proxyPipe(t)
		release := make(chan struct{})
		t.Cleanup(func() { close(release) })
		done := make(chan error, 1)
		go func() {
			if _, err := io.WriteString(client, proxyPrefix); err != nil {
				done <- err
				return
			}
			select {
			case <-release:
				done <- nil
				return
			case <-time.After(250 * time.Millisecond):
			}
			_, err := io.WriteString(client, "later")
			done <- err
		}()
		connection, err := prepareProxyV1(server, proxyExpected, 100*time.Millisecond)
		if err != nil {
			t.Fatal(err)
		}
		got := make([]byte, 5)
		if _, err := io.ReadFull(connection, got); err != nil || string(got) != "later" {
			t.Fatalf("application deadline inherited: bytes=%q err=%v", got, err)
		}
		proxyDone(t, done)
	})
	t.Run("timeout-silent", func(t *testing.T) { server, client := proxyPipe(t); proxyTimeout(t, server, client) })
	t.Run("timeout-partial", func(t *testing.T) {
		server, client := proxyPipe(t)
		done := make(chan error, 1)
		go func() { _, err := io.WriteString(client, "PROXY TCP4 "); done <- err }()
		proxyTimeout(t, server, client)
		proxyDone(t, done)
	})
	t.Run("malformed", func(t *testing.T) {
		server, client := proxyPipe(t)
		done := make(chan error, 1)
		go func() { _, err := io.WriteString(client, "PROXY UNKNOWN\r\n"); done <- err }()
		connection, err := prepareProxyV1(server, proxyExpected, time.Second)
		if connection != nil || err == nil {
			t.Fatal("malformed connection admitted")
		}
		proxyDone(t, done)
		proxyClosed(t, client)
	})
	for _, kind := range []string{"initial-deadline-failure", "clear-deadline-failure"} {
		t.Run(kind, func(t *testing.T) {
			server, client := proxyPipe(t)
			failure := errors.New("synthetic deadline failure")
			wrapped := &proxyDeadlineFailure{Conn: server, failure: failure, clear: kind == "clear-deadline-failure"}
			var done chan error
			if wrapped.clear {
				done = make(chan error, 1)
				go func() { _, err := io.WriteString(client, proxyPrefix); done <- err }()
			}
			connection, err := prepareProxyV1(wrapped, proxyExpected, time.Second)
			if connection != nil || !errors.Is(err, failure) {
				t.Fatalf("connection=%v err=%v", connection, err)
			}
			if done != nil {
				proxyDone(t, done)
			}
			proxyClosed(t, client)
		})
	}
	t.Run("invalid-budget", func(t *testing.T) {
		for _, budget := range []time.Duration{0, -time.Second, 3*time.Second + time.Nanosecond} {
			server, client := proxyPipe(t)
			connection, err := prepareProxyV1(server, proxyExpected, budget)
			if connection != nil || err == nil {
				t.Fatal("invalid budget admitted")
			}
			proxyClosed(t, client)
		}
	})
}

type proxyDeadlineFailure struct {
	net.Conn
	failure error
	clear   bool
}

func (c *proxyDeadlineFailure) SetReadDeadline(deadline time.Time) error {
	if deadline.IsZero() == c.clear {
		return c.failure
	}
	return c.Conn.SetReadDeadline(deadline)
}

func TestProxyV1TCP(t *testing.T) {
	if runtime.GOOS != "openbsd" || os.Getenv("AEGVIUM_NATIVE_REPEAT") != "1" {
		t.Skip("owned OpenBSD native repeat only")
	}
	for _, kind := range []string{"handoff", "timeout"} {
		t.Run(kind, func(t *testing.T) {
			listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = listener.Close() })
			if err := listener.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			client, err := net.DialTimeout("tcp4", listener.Addr().String(), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = client.Close() })
			if err := client.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			server, err := listener.AcceptTCP()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = server.Close() })
			if err := listener.Close(); err != nil {
				t.Fatal(err)
			}
			t.Log("tcp-listener closed=true")
			if kind == "timeout" {
				proxyTimeout(t, server, client)
				return
			}
			done := make(chan error, 1)
			go func() { _, err := io.WriteString(client, proxyPrefix+"native TCP bytes"); done <- err }()
			connection, err := prepareProxyV1(server, proxyExpected, 3*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			got := make([]byte, len("native TCP bytes"))
			_, err = io.ReadFull(connection, got)
			if err != nil || string(got) != "native TCP bytes" || connection.RemoteAddr().String() != client.LocalAddr().String() || !strings.HasPrefix(connection.RemoteAddr().String(), "127.0.0.1:") {
				t.Fatalf("TCP handoff bytes=%q err=%v", got, err)
			}
			proxyDone(t, done)
			_ = connection.Close()
			proxyClosed(t, client)
		})
	}
}
