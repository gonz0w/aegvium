// SPDX-License-Identifier: BSD-3-Clause
package commissionplace

import (
	"errors"
	"strconv"
	"strings"
)

// Exact fresh-target readback. This does not create an account, authenticate a
// process, qualify OS databases or grant launch authority.
func accountIdentity(master, group string) (int, error) {
	fail := errors.New("fresh account readback incomplete")
	if len(master) > 262144 || len(group) > 262144 {
		return 0, fail
	}
	uid, gid := "", ""
	found := 0
	for _, line := range strings.Split(master, "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p := strings.Split(line, ":")
		if len(p) > 0 && p[0] == "_aegvium" {
			found++
			if len(p) != 10 || p[1] != "*" || p[7] != "Aegvium inspector" || p[8] != "/var/empty" || p[9] != "/sbin/nologin" {
				return 0, fail
			}
			uid, gid = p[2], p[3]
		}
	}
	n, e := strconv.ParseUint(uid, 10, 31)
	if e != nil || n == 0 || uid != gid || strconv.FormatUint(n, 10) != uid || found != 1 {
		return 0, fail
	}
	for _, line := range strings.Split(master, "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p := strings.Split(line, ":")
		if len(p) != 10 {
			return 0, fail
		}
		u, e1 := strconv.ParseUint(p[2], 10, 32)
		g, e2 := strconv.ParseUint(p[3], 10, 32)
		if e1 != nil || e2 != nil || u == 4294967295 || g == 4294967295 ||
			p[0] != "_aegvium" && (u == n || g == n) {
			return 0, fail
		}
	}
	found = 0
	for _, line := range strings.Split(group, "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p := strings.Split(line, ":")
		if len(p) != 4 {
			if line != "" {
				return 0, fail
			}
			continue
		}
		if p[0] == "_aegvium" {
			found++
			if p[2] != gid || p[3] != "" {
				return 0, fail
			}
		}
		for _, member := range strings.Split(p[3], ",") {
			if member == "_aegvium" {
				return 0, fail
			}
		}
		g, e := strconv.ParseUint(p[2], 10, 32)
		if e != nil || g == 4294967295 || g == n && p[0] != "_aegvium" {
			return 0, fail
		}
	}
	if found != 1 {
		return 0, fail
	}
	return int(n), nil
}

// Existing stock-package principal only. Retained package source declares604;
// the exact OpenBSD8.0 package/account/drop/chroot profile remains unqualified.
// No account is created or repaired and no user-supplied numeric ID is accepted.
func frontendAccountIdentity(master, group string) bool {
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
