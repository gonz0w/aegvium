// SPDX-License-Identifier: BSD-3-Clause
package spike

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"
)

// Metadata is an assertion from the sender, not authenticated client identity.
// RemoteAddr remains the transport peer; Read preserves prefix read-ahead.
type proxyV1Conn struct {
	net.Conn
	reader   *bufio.Reader
	identity proxyIdentity
}

func (c *proxyV1Conn) Read(p []byte) (int, error) { return c.reader.Read(p) }

// Takes ownership of a fresh connection and its read-deadline state.
// On success the caller owns Close and application deadline policy.
func prepareProxyV1(connection net.Conn, expected netip.AddrPort, budget time.Duration) (*proxyV1Conn, error) {
	if connection == nil {
		return nil, errors.New("missing PROXY connection")
	}
	accepted := false
	defer func() {
		if !accepted {
			_ = connection.Close()
		}
	}()
	if budget <= 0 || budget > 3*time.Second {
		return nil, errors.New("invalid PROXY prefix budget")
	}
	if err := connection.SetReadDeadline(time.Now().Add(budget)); err != nil {
		return nil, fmt.Errorf("set PROXY deadline: %w", err)
	}
	reader := bufio.NewReader(connection)
	identity, err := readProxyV1(reader, expected)
	if err != nil {
		return nil, err
	}
	if err := connection.SetReadDeadline(time.Time{}); err != nil {
		return nil, fmt.Errorf("clear PROXY deadline: %w", err)
	}
	accepted = true
	return &proxyV1Conn{Conn: connection, reader: reader, identity: identity}, nil
}
