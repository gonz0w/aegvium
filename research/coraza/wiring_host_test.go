// SPDX-License-Identifier: BSD-3-Clause
package spike

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"
)

func TestWiringFixture(t *testing.T) {
	expected := netip.MustParseAddrPort("127.0.0.1:18120")
	f, err := startWiringFixture(expected, [3]uint16{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := f.close(); err != nil {
			t.Error(err)
		}
	})
	probe := func(want int) {
		t.Helper()
		c, e := net.DialTimeout("tcp4", f.listeners[2].Addr().String(), time.Second)
		if e != nil {
			t.Fatal(e)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		_, e = io.WriteString(c, "HEAD /ready HTTP/1.0\r\n\r\n")
		if e != nil {
			t.Fatal(e)
		}
		r, e := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: "HEAD"})
		if e != nil {
			t.Fatal(e)
		}
		defer r.Body.Close()
		if r.StatusCode != want {
			t.Fatalf("health %d", r.StatusCode)
		}
	}
	request := func(phase int, id, path string, prefix bool) (int, string, error) {
		c, e := net.DialTimeout("tcp4", f.listeners[1].Addr().String(), time.Second)
		if e != nil {
			return 0, "", e
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		wire := ""
		if prefix {
			wire = "PROXY TCP4 127.0.0.1 127.0.0.1 12345 18120\r\n"
		}
		wire += fmt.Sprintf("GET %s HTTP/1.1\r\nHost: fixture\r\nConnection: close\r\nX-Aegvium-Phase: %d\r\nX-Aegvium-Request: %s\r\n\r\n", path, phase, id)
		if _, e = io.WriteString(c, wire); e != nil {
			return 0, "", e
		}
		r, e := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: "GET"})
		if e != nil {
			return 0, "", e
		}
		defer r.Body.Close()
		b, e := io.ReadAll(io.LimitReader(r.Body, 64))
		return r.StatusCode, string(b), e
	}
	t.Run("initial-down", func(t *testing.T) {
		if e := f.apply(1, "down"); e != nil {
			t.Fatal(e)
		}
		probe(503)
		if _, _, e := request(1, "benign", "/allowed", true); e == nil {
			t.Fatal("down admitted")
		}
		if len(f.snapshot()) != 0 {
			t.Fatal("down events")
		}
	})
	t.Run("ready-inspection-sink", func(t *testing.T) {
		if e := f.apply(2, "ready"); e != nil {
			t.Fatal(e)
		}
		probe(200)
		code, b, e := request(2, "benign", "/allowed", true)
		if e != nil || code != 200 || b != "synthetic sink\n" {
			t.Fatalf("%d %q %v", code, b, e)
		}
		code, _, e = request(2, "denied", "/forbidden", true)
		if e != nil || code != 403 {
			t.Fatalf("denial %d %v", code, e)
		}
		events := f.snapshot()
		if len(events) != 3 || events[0].Role != "sink" || events[1].Status != 200 || events[2].Status != 403 {
			t.Fatalf("%+v", events)
		}
		for _, event := range events {
			if event.Phase != 2 || (event.Role == "sink" && event.Request != "benign") {
				t.Fatalf("wrong identity %+v", event)
			}
		}
	})
	t.Run("stale-duplicate-bare-rejected", func(t *testing.T) {
		before := len(f.snapshot())
		for _, phase := range []int{1, 2} {
			code, _, e := request(phase, "benign", "/allowed", true)
			if e != nil || code != 400 {
				t.Fatalf("%d %v", code, e)
			}
		}
		if _, _, e := request(2, "benign", "/allowed", false); e == nil {
			t.Fatal("bare HTTP admitted")
		}
		probe(200)
		if len(f.snapshot()) != before {
			t.Fatal("invalid/health events")
		}
		if e := f.apply(2, "ready"); e == nil {
			t.Fatal("stale phase")
		}
		if e := f.apply(3, "arbitrary"); e == nil {
			t.Fatal("unknown operation")
		}
	})
	t.Run("down-recovered", func(t *testing.T) {
		if e := f.apply(3, "down"); e != nil {
			t.Fatal(e)
		}
		probe(503)
		before := len(f.snapshot())
		if _, _, e := request(3, "benign", "/allowed", true); e == nil {
			t.Fatal("down admitted")
		}
		if len(f.snapshot()) != before {
			t.Fatal("down event")
		}
		if e := f.apply(4, "ready"); e != nil {
			t.Fatal(e)
		}
		probe(200)
		code, _, e := request(4, "benign", "/allowed", true)
		if e != nil || code != 200 {
			t.Fatalf("recovered %d %v", code, e)
		}
		code, _, e = request(4, "denied", "/forbidden", true)
		if e != nil || code != 403 {
			t.Fatalf("recovered denial %d %v", code, e)
		}
		events := f.snapshot()
		if len(events) != 6 || events[3].Phase != 4 || events[4].Phase != 4 || events[5].Phase != 4 || events[5].Status != 403 {
			t.Fatalf("recovered receipts %+v", events)
		}
	})
	t.Run("terminal-close-and-cleanup", func(t *testing.T) {
		if e := f.apply(5, "close"); e != nil {
			t.Fatal(e)
		}
		probe(503)
		if e := f.apply(6, "ready"); e == nil {
			t.Fatal("closed receiver recovered")
		}
		if e := f.close(); e != nil {
			t.Fatal(e)
		}
		for _, l := range f.listeners {
			c, e := net.DialTimeout("tcp4", l.Addr().String(), 200*time.Millisecond)
			if e == nil {
				c.Close()
				t.Fatal("listener survived")
			}
		}
	})
}

func TestWiringBusyPhase(t *testing.T) {
	f, err := startWiringFixture(netip.MustParseAddrPort("127.0.0.1:18120"), [3]uint16{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := f.close(); err != nil {
			t.Error(err)
		}
	})
	if err := f.apply(1, "ready"); err != nil {
		t.Fatal(err)
	}
	started, release := make(chan struct{}), make(chan struct{})
	original := f.transport.DialContext
	f.transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		close(started)
		select {
		case <-release:
			return original(ctx, network, address)
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	c, err := net.DialTimeout("tcp4", f.listeners[1].Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	_, err = io.WriteString(c, "PROXY TCP4 127.0.0.1 127.0.0.1 12345 18120\r\nGET /allowed HTTP/1.1\r\nHost: fixture\r\nConnection: close\r\nX-Aegvium-Phase: 1\r\nX-Aegvium-Request: benign\r\n\r\n")
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		close(release)
		t.Fatal("forward did not start")
	}
	if err := f.apply(2, "down"); err == nil {
		close(release)
		t.Fatal("phase changed during active forwarding")
	}
	close(release)
	r, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: "GET"})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, 64))
	if err != nil || r.StatusCode != 200 || string(body) != "synthetic sink\n" {
		t.Fatalf("%d %q %v", r.StatusCode, body, err)
	}
	if err := f.apply(2, "down"); err != nil {
		t.Fatal(err)
	}
	events := f.snapshot()
	if len(events) != 2 || events[0].Phase != 1 || events[1].Phase != 1 {
		t.Fatalf("phase attribution %+v", events)
	}
}
