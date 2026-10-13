// SPDX-License-Identifier: BSD-3-Clause
// Fixture-only relayd checker candidate; not an installed appliance service.
package main

import (
	"github.com/gonz0w/aegvium/research/coraza/internal/readyprobe"
	"net"
	"net/netip"
	"os"
	"time"
)

// Normalize unexpected returns/panics in this goroutine to relayd's down result.
// Runtime fatal errors and external positive exits are not covered by recover.
func checkerExit(probe func() int) (result int) {
	defer func() {
		if recover() != nil {
			result = 0
		}
	}()
	if probe() != 1 {
		return 0
	}
	return 1
}
func main() {
	os.Exit(checkerExit(func() int {
		return readyprobe.Run(os.Args[1:], netip.MustParseAddrPort("127.0.0.1:18085"), 200*time.Millisecond, net.DialTimeout)
	}))
}
