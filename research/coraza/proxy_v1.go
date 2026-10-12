// SPDX-License-Identifier: BSD-3-Clause
package spike

import (
	"bufio"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// This restricted experiment neither authenticates peers nor sets socket deadlines.
// Callers must keep the reader to preserve any buffered application bytes.
const proxyV1Maximum = 56

type proxyIdentity struct {
	source, destination netip.AddrPort
}

func readProxyV1(reader *bufio.Reader, expected netip.AddrPort) (proxyIdentity, error) {
	var zero proxyIdentity
	if !expected.IsValid() || !expected.Addr().Is4() || expected.Port() == 0 {
		return zero, errors.New("invalid expected PROXY destination")
	}
	line := make([]byte, 0, proxyV1Maximum)
	for len(line) < proxyV1Maximum {
		b, err := reader.ReadByte()
		if err != nil {
			return zero, fmt.Errorf("incomplete PROXY prefix: %w", err)
		}
		line = append(line, b)
		if b != '\n' {
			continue
		}
		if len(line) < 2 || line[len(line)-2] != '\r' {
			return zero, errors.New("invalid PROXY terminator")
		}
		fields := strings.Split(string(line[:len(line)-2]), " ")
		if len(fields) != 6 || fields[0] != "PROXY" || fields[1] != "TCP4" {
			return zero, errors.New("unsupported PROXY prefix")
		}
		endpoints := [2]netip.AddrPort{}
		for i := range endpoints {
			addr, err := netip.ParseAddr(fields[2+i])
			if err != nil || !addr.Is4() || addr.String() != fields[2+i] {
				return zero, errors.New("invalid PROXY IPv4 address")
			}
			port, err := strconv.ParseUint(fields[4+i], 10, 16)
			if err != nil || port == 0 || strconv.FormatUint(port, 10) != fields[4+i] {
				return zero, errors.New("invalid PROXY port")
			}
			endpoints[i] = netip.AddrPortFrom(addr, uint16(port))
		}
		if endpoints[1] != expected {
			return zero, errors.New("unexpected PROXY destination")
		}
		return proxyIdentity{source: endpoints[0], destination: endpoints[1]}, nil
	}
	return zero, errors.New("PROXY prefix exceeds byte limit")
}
