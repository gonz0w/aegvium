// SPDX-License-Identifier: BSD-3-Clause
package spike

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestReadyProbe(t *testing.T) {
	endpoint := netip.MustParseAddrPort("127.0.0.1:18085")
	cases := []struct {
		name, response string
		want           int
	}{
		{"ready", "HTTP/1.0 200 OK\r\nCache-Control: no-store\r\n\r\n", 1},
		{"unavailable", "HTTP/1.0 503 Service Unavailable\r\nCache-Control: no-store\r\n\r\n", 0},
		{"redirect", "HTTP/1.0 302 Found\r\nLocation: http://example.invalid/\r\n\r\n", 0},
		{"malformed", "garbage\r\n\r\n", 0},
		{"oversized", "HTTP/1.0 200 OK\r\nX: " + strings.Repeat("a", 5000) + "\r\nCache-Control: no-store\r\n\r\n", 0},
		{"body", "HTTP/1.0 200 OK\r\nCache-Control: no-store\r\n\r\nx", 0},
		{"missing-no-store", "HTTP/1.0 200 OK\r\n\r\n", 0},
		{"keepalive", "HTTP/1.1 200 OK\r\nCache-Control: no-store\r\n\r\n", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server, client := net.Pipe()
			defer server.Close()
			defer client.Close()
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer server.Close()
				r := bufio.NewReader(server)
				request, err := httpProbeRequest(r)
				if err == nil && request == "HEAD /ready HTTP/1.0\r\n\r\n" {
					_, _ = io.WriteString(server, tc.response)
				}
			}()
			dial := func(network, address string, timeout time.Duration) (net.Conn, error) {
				if network != "tcp4" || address != endpoint.String() || timeout != time.Second {
					t.Fatal("probe destination changed")
				}
				return client, nil
			}
			if got := readyProbe([]string{"127.0.0.1"}, endpoint, time.Second, dial); got != tc.want {
				t.Fatalf("result=%d want=%d", got, tc.want)
			}
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("fixture peer did not join")
			}
		})
	}
	t.Run("validation", func(t *testing.T) {
		dial := func(string, string, time.Duration) (net.Conn, error) {
			t.Fatal("invalid input dialed")
			return nil, nil
		}
		for _, args := range [][]string{nil, {"localhost"}, {"127.0.0.1", "extra"}, {"127.0.0.2"}, {"127.0.0.1;id"}} {
			if readyProbe(args, endpoint, time.Second, dial) != 0 {
				t.Fatal("argument admitted")
			}
		}
		for _, ep := range []netip.AddrPort{{}, netip.MustParseAddrPort("127.0.0.1:0"), netip.MustParseAddrPort("192.0.2.1:80")} {
			if readyProbe([]string{"127.0.0.1"}, ep, time.Second, dial) != 0 {
				t.Fatal("endpoint admitted")
			}
		}
		for _, budget := range []time.Duration{0, -1, 2 * time.Second} {
			if readyProbe([]string{"127.0.0.1"}, endpoint, budget, dial) != 0 {
				t.Fatal("budget admitted")
			}
		}
	})
	t.Run("dial-failure", func(t *testing.T) {
		if readyProbe([]string{"127.0.0.1"}, endpoint, time.Second, func(string, string, time.Duration) (net.Conn, error) { return nil, errors.New("fixture refusal") }) != 0 {
			t.Fatal("dial failure healthy")
		}
	})
	t.Run("silent-timeout", func(t *testing.T) {
		server, client := net.Pipe()
		defer server.Close()
		defer client.Close()
		if readyProbe([]string{"127.0.0.1"}, endpoint, 50*time.Millisecond, func(string, string, time.Duration) (net.Conn, error) { return client, nil }) != 0 {
			t.Fatal("silent peer healthy")
		}
	})
}
func httpProbeRequest(r *bufio.Reader) (string, error) {
	var result strings.Builder
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return "", err
		}
		result.WriteString(line)
		if line == "\r\n" {
			return result.String(), nil
		}
	}
}
