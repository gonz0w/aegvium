// SPDX-License-Identifier: BSD-3-Clause
package frontendconfig

import (
	"strconv"
	"strings"
)

// Existing stock-package principal only. Retained package source declares604;
// the exact OpenBSD8.0 package/account/drop/chroot profile remains unqualified.
// No account is created or repaired and no user-supplied numeric ID is accepted.
func PackagePrincipalData(master, group string) bool {
	if len(master) > 262144 || len(group) > 262144 {
		return false
	}
	found := 0
	for _, line := range strings.Split(master, "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p := strings.Split(line, ":")
		if len(p) != 10 {
			return false
		}
		uid, e1 := strconv.ParseUint(p[2], 10, 32)
		gid, e2 := strconv.ParseUint(p[3], 10, 32)
		if e1 != nil || e2 != nil || uid == 4294967295 || gid == 4294967295 {
			return false
		}
		if p[0] == "_haproxy" {
			found++
			if p[1] != "*" || p[2] != "604" || p[3] != "604" || p[8] != "/var/empty" || p[9] != "/sbin/nologin" {
				return false
			}
		} else if uid == 604 || gid == 604 {
			return false
		}
	}
	if found != 1 {
		return false
	}
	found = 0
	for _, line := range strings.Split(group, "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p := strings.Split(line, ":")
		if len(p) != 4 {
			return false
		}
		gid, e := strconv.ParseUint(p[2], 10, 32)
		if e != nil || gid == 4294967295 {
			return false
		}
		if p[0] == "_haproxy" {
			found++
			if p[2] != "604" || p[3] != "" {
				return false
			}
		} else if gid == 604 {
			return false
		}
		for _, member := range strings.Split(p[3], ",") {
			if member == "_haproxy" {
				return false
			}
		}
	}
	return found == 1
}
