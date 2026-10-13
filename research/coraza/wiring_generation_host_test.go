// SPDX-License-Identifier: BSD-3-Clause
package spike

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Reuse the same ports and request identity only after the prior owner joins.
func TestWiringFreshGenerationRebind(t *testing.T) {
	var ports [3]uint16
	previous := ""
	for generation := 1; generation <= 2; generation++ {
		f, err := startWiringFixture(netip.MustParseAddrPort("127.0.0.1:18120"), ports)
		if err != nil {
			t.Fatal(err)
		}
		for i, listener := range f.listeners {
			ports[i] = uint16(listener.Addr().(*net.TCPAddr).Port)
		}
		dir := t.TempDir()
		control, receipt := filepath.Join(dir, "phase"), filepath.Join(dir, "state.json")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		t.Cleanup(func() {
			cancel()
			if err := f.close(); err != nil {
				t.Error(err)
			}
		})
		done := make(chan error, 1)
		go func() { done <- runWiringControls(ctx, f, control, receipt) }()
		read := func(phase uint64, count int) wiringAck {
			t.Helper()
			until := time.Now().Add(2 * time.Second)
			for time.Now().Before(until) {
				var ack wiringAck
				b, err := os.ReadFile(receipt)
				if err == nil && json.Unmarshal(b, &ack) == nil && ack.Phase == phase && len(ack.Events) == count {
					return ack
				}
				time.Sleep(10 * time.Millisecond)
			}
			t.Fatal("fresh generation acknowledgement timeout")
			return wiringAck{}
		}
		publish := func(phase int, op string) {
			t.Helper()
			tmp := filepath.Join(dir, "phase.tmp")
			if err := os.WriteFile(tmp, []byte(fmt.Sprintf("%d\t%s\n", phase, op)), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(tmp, control); err != nil {
				t.Fatal(err)
			}
		}
		initial := read(0, 0)
		if initial.Generation == previous || len(initial.Generation) != 32 || initial.Ready || initial.Terminal || initial.Cleaned {
			t.Fatalf("stale startup: %+v", initial)
		}
		publish(1, "ready")
		if ack := read(1, 0); !ack.Ready || ack.Generation != initial.Generation {
			t.Fatalf("ready: %+v", ack)
		}
		c, err := net.DialTimeout("tcp4", f.listeners[1].Addr().String(), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		_, err = fmt.Fprint(c, "PROXY TCP4 127.0.0.1 127.0.0.1 12345 18120\r\nGET /allowed HTTP/1.1\r\nHost: fixture\r\nConnection: close\r\nX-Aegvium-Phase: 1\r\nX-Aegvium-Request: benign\r\n\r\n")
		if err != nil {
			c.Close()
			t.Fatal(err)
		}
		response, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: "GET"})
		if err != nil {
			c.Close()
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		c.Close()
		if err != nil || response.StatusCode != 200 || string(body) != "synthetic sink\n" {
			t.Fatalf("fresh forwarding: %v %q", err, body)
		}
		if ack := read(1, 2); ack.Events[0].Role != "sink" || ack.Events[1].Role != "inspection" {
			t.Fatalf("fresh counters: %+v", ack)
		}
		stop := 2
		if generation == 1 {
			publish(2, "health-refused")
			if ack := read(2, 2); !ack.Ready || ack.Terminal {
				t.Fatalf("refusal: %+v", ack)
			}
			stop = 3
		}
		publish(stop, "stop")
		ack := read(uint64(stop), 2)
		if ack.Ready || !ack.Terminal || !ack.Cleaned || ack.Generation != initial.Generation {
			t.Fatalf("stop: %+v", ack)
		}
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("generation did not join")
		}
		cancel()
		for _, listener := range f.listeners {
			c, err := net.DialTimeout("tcp4", listener.Addr().String(), 100*time.Millisecond)
			if err == nil {
				c.Close()
				t.Fatal("prior generation listener survived Stop")
			}
		}
		previous = initial.Generation
	}
}
