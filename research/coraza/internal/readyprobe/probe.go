// SPDX-License-Identifier: BSD-3-Clause
package readyprobe

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/netip"
	"time"
)

type Dial func(network, address string, timeout time.Duration) (net.Conn, error)

// Research core only: the caller supplies a fixed fixture endpoint, never a URL
// derived from relayd's host argument. Result 1 means healthy; all errors mean 0.
// Standalone process and stock-relayd health behavior require separate evidence.
func Run(args []string, endpoint netip.AddrPort, budget time.Duration, dial Dial) int {
	if len(args) != 1 || args[0] != "127.0.0.1" || !endpoint.IsValid() || endpoint.Addr() != netip.MustParseAddr("127.0.0.1") || endpoint.Port() == 0 || budget <= 0 || budget > time.Second || dial == nil {
		return 0
	}
	deadline := time.Now().Add(budget)
	connection, err := dial("tcp4", endpoint.String(), budget)
	if err != nil || connection == nil {
		if connection != nil {
			_ = connection.Close()
		}
		return 0
	}
	defer connection.Close()
	if err = connection.SetDeadline(deadline); err != nil {
		return 0
	}
	if _, err = io.WriteString(connection, "HEAD /ready HTTP/1.0\r\n\r\n"); err != nil {
		return 0
	}
	// Bound response parsing even if a peer sends an arbitrarily long header.
	reader := bufio.NewReader(io.LimitReader(connection, 4096))
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodHead})
	if err != nil {
		return 0
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || !response.Close || response.ContentLength > 0 || len(response.TransferEncoding) != 0 || response.Header.Get("Cache-Control") != "no-store" {
		return 0
	}
	// Require actual peer EOF, not LimitReader's synthetic EOF at the size limit.
	if reader.Buffered() != 0 {
		return 0
	}
	n, err := connection.Read(make([]byte, 1))
	if n != 0 || err != io.EOF {
		return 0
	}
	return 1
}
