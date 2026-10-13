// SPDX-License-Identifier: BSD-3-Clause
package spike

import (
	"github.com/gonz0w/aegvium/research/coraza/internal/readyprobe"
	"net/netip"
	"time"
)

type readyDial = readyprobe.Dial

// Preserve the isolated research harness; shared core is internal, not a connector API.
func readyProbe(args []string, endpoint netip.AddrPort, budget time.Duration, dial readyDial) int {
	return readyprobe.Run(args, endpoint, budget, dial)
}
