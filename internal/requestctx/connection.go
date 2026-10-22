// SPDX-License-Identifier: BSD-3-Clause
package requestctx

import (
	"net/netip"
	"strings"
)

// Pure H1/3 syntax only. Actual authenticated same-request provenance belongs to
// the receiver and frontend; tuples are never destinations or admission tokens.
func parseConnection(value string) (remote, local netip.AddrPort, ok bool) {
	if len(value) < 1 || len(value) > 43 {
		return
	}
	a, b, found := strings.Cut(value, "/")
	if !found {
		return
	}
	remote, err := netip.ParseAddrPort(a)
	if err != nil || !remote.Addr().Is4() || remote.Port() == 0 || remote.String() != a {
		return netip.AddrPort{}, netip.AddrPort{}, false
	}
	local, err = netip.ParseAddrPort(b)
	if err != nil || !local.Addr().Is4() || local.Port() == 0 || local.String() != b {
		return netip.AddrPort{}, netip.AddrPort{}, false
	}
	return remote, local, true
}
