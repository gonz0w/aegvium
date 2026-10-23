// SPDX-License-Identifier: BSD-3-Clause
package localcontrol

import (
	"strconv"
	"strings"
	"time"
)

const stopPrefix = "AGCTL2 STOP "
const StopBudgetMillis int64 = 4000

// Epoch is timing data from the existing root client, never ownership/cleanup
// proof. Canonical positive milliseconds fit the unchanged32-byte wire cap.
func Epoch(text string) (int64, error) {
	if len(text) < 1 || len(text) > 19 || text[0] == '0' {
		return 0, ErrUnavailable
	}
	for _, c := range text {
		if c < '0' || c > '9' {
			return 0, ErrUnavailable
		}
	}
	n, e := strconv.ParseInt(text, 10, 64)
	if e != nil || n <= 0 || n > 1<<63-1-StopBudgetMillis {
		return 0, ErrUnavailable
	}
	return n, nil
}
func StopRequest(origin int64) (string, error) {
	text := strconv.FormatInt(origin, 10)
	if _, e := Epoch(text); e != nil {
		return "", e
	}
	return stopPrefix + text + "\n", nil
}
func ParseRequest(raw []byte, uid, gid uint32) (bool, int64, error) {
	if uid != 0 || gid != 0 {
		return false, 0, ErrUnavailable
	}
	if strings.HasPrefix(string(raw), stopPrefix) && len(raw) > len(stopPrefix) && raw[len(raw)-1] == '\n' {
		n, e := Epoch(string(raw[len(stopPrefix) : len(raw)-1]))
		return e == nil, n, e
	}
	stop, e := Request(raw, uid, gid)
	return stop, 0, e
}

// Remaining includes notification time. Expiry is0, never fresh grace; future
// clocks/epochs refuse. The Go sample must precede the kernel clock sample.
func Remaining(origin, now int64) (time.Duration, error) {
	if _, e := Epoch(strconv.FormatInt(origin, 10)); e != nil || now < origin {
		return 0, ErrUnavailable
	}
	elapsed := now - origin
	if elapsed >= StopBudgetMillis {
		return 0, nil
	}
	return time.Duration(StopBudgetMillis-elapsed) * time.Millisecond, nil
}
func ConservativeOrigin(sample time.Time, origin, now int64) (time.Time, error) {
	left, e := Remaining(origin, now)
	if e != nil || sample.IsZero() {
		return time.Time{}, ErrUnavailable
	}
	return sample.Add(left - 4*time.Second), nil
}
