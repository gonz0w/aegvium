//go:build openbsd && (amd64 || arm64) && (aegvium_frontend_source || aegvium_service_source)

// SPDX-License-Identifier: BSD-3-Clause
package localcontrol

import "golang.org/x/sys/unix"

// KernelMillisSource shares S's CLOCK_MONOTONIC basis. No wall clock, caller
// offset or receipt substitutes for the actual native read. Gates remain false.
func KernelMillisSource() (int64, error) {
	var t unix.Timespec
	if unix.ClockGettime(unix.CLOCK_MONOTONIC, &t) != nil || t.Sec < 0 || t.Sec > (1<<63-1)/1000 || t.Nsec < 0 || t.Nsec >= 1e9 || t.Sec*1000 > 1<<63-1-t.Nsec/1e6 {
		return 0, ErrUnavailable
	}
	return t.Sec*1000 + t.Nsec/1e6, nil
}
