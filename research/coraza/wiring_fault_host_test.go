// SPDX-License-Identifier: BSD-3-Clause
package spike

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/gonz0w/aegvium/research/coraza/internal/readyprobe"
)

func TestWiringHealthFaults(t *testing.T) {
	for _, mode := range []string{"health-silent", "health-malformed", "health-redirect", "health-refused"} {
		t.Run(mode, func(t *testing.T) {
			f, err := startWiringFixture(netip.MustParseAddrPort("127.0.0.1:18120"), [3]uint16{})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := f.close(); err != nil {
					t.Error(err)
				}
			})
			health := netip.MustParseAddrPort(f.listeners[2].Addr().String())
			probe := func() int {
				return readyprobe.Run([]string{"127.0.0.1"}, health, 200*time.Millisecond, net.DialTimeout)
			}
			if err := f.apply(1, "ready"); err != nil {
				t.Fatal(err)
			}
			if probe() != 1 {
				t.Fatal("initial health failed")
			}
			if err := f.apply(2, mode); err != nil {
				t.Fatal(err)
			}
			if probe() != 0 || !f.receiver.Ready() || len(f.snapshot()) != 0 {
				t.Fatal("health fault changed data readiness or produced events")
			}
			c, err := net.DialTimeout("tcp4", f.listeners[1].Addr().String(), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(2 * time.Second))
			_, err = fmt.Fprintf(c, "PROXY TCP4 127.0.0.1 127.0.0.1 12345 18120\r\nGET /allowed HTTP/1.1\r\nHost: fixture\r\nConnection: close\r\nX-Aegvium-Phase: 2\r\nX-Aegvium-Request: witness\r\n\r\n")
			if err != nil {
				t.Fatal(err)
			}
			response, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: "GET"})
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(response.Body)
			response.Body.Close()
			if err != nil || response.StatusCode != 200 || string(body) != "synthetic sink\n" {
				t.Fatalf("data witness: %v %q", err, body)
			}
			events := f.snapshot()
			if len(events) != 2 || events[0].Request != "witness" || events[0].Role != "sink" || events[1].Role != "inspection" {
				t.Fatalf("%+v", events)
			}
			if mode == "health-refused" {
				if err := f.apply(3, "ready"); err == nil {
					t.Fatal("closed health listener recovered without new generation")
				}
			} else {
				if err := f.apply(3, "ready"); err != nil {
					t.Fatal(err)
				}
				if probe() != 1 || len(f.snapshot()) != 2 {
					t.Fatal("health recovery failed or added application events")
				}
			}
			if err := f.close(); err != nil {
				t.Fatal(err)
			}
			for _, listener := range f.listeners {
				connection, err := net.DialTimeout("tcp4", listener.Addr().String(), 100*time.Millisecond)
				if err == nil {
					connection.Close()
					t.Fatal("listener survived cleanup")
				}
			}
		})
	}
}
