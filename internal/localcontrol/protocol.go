// SPDX-License-Identifier: BSD-3-Clause
// Package localcontrol contains only Aegvium's fixed local service protocol.
// Replies are owner observations, never readiness or reclamation capabilities.
package localcontrol

import "errors"

var ErrUnavailable = errors.New("local owner control unavailable")

const Status = "AGCTL1 STATUS\n"
const Stop = "AGCTL1 STOP\n"

func Request(raw []byte, uid, gid uint32) (stop bool, err error) {
	if uid != 0 || gid != 0 {
		return false, ErrUnavailable
	}
	switch string(raw) {
	case Status:
		return false, nil
	case Stop:
		return true, nil
	}
	return false, ErrUnavailable
}

func Reply(owner, phase string) (string, error) {
	if owner != "inspector" && owner != "frontend" {
		return "", ErrUnavailable
	}
	switch phase {
	case "starting", "owned-running", "retiring", "terminal", "uncertain":
		return "AGCTL1 " + owner + " " + phase + " qualified=0\n", nil
	}
	return "", ErrUnavailable
}

func ValidReply(owner string, raw []byte) bool {
	for _, phase := range []string{"starting", "owned-running", "retiring", "terminal", "uncertain"} {
		want, err := Reply(owner, phase)
		if err == nil && string(raw) == want {
			return true
		}
	}
	return false
}
