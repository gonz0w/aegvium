// SPDX-License-Identifier: BSD-3-Clause
package localcontrol

import "testing"

func TestLocalControlExactRootOnlyWire(t *testing.T) {
	for _, raw := range []string{Status, Stop} {
		stop, err := Request([]byte(raw), 0, 0)
		if err != nil || stop != (raw == Stop) {
			t.Fatal("exact independent command refused")
		}
		for _, ids := range [][2]uint32{{1, 0}, {0, 1}, {1, 1}, {^uint32(0), 0}} {
			if _, err := Request([]byte(raw), ids[0], ids[1]); err == nil {
				t.Fatal("nonroot peer admitted")
			}
		}
	}
	for _, raw := range []string{"", "AGCTL1 STOP", "AGCTL1 STOP\r\n", "AGCTL1 STOP\nX", "AGCTL1 STOP\nAGCTL1 STATUS\n", "AGCTL1 START\n", "AGCTL1 STOP 1\n", "agctl1 STOP\n"} {
		if _, err := Request([]byte(raw), 0, 0); err == nil {
			t.Fatal("partial/extended/foreign command admitted")
		}
	}
}
func TestLocalControlRepliesNeverGrantReadiness(t *testing.T) {
	for _, owner := range []string{"inspector", "frontend"} {
		for _, phase := range []string{"starting", "owned-running", "retiring", "terminal", "uncertain"} {
			raw, err := Reply(owner, phase)
			if err != nil || len(raw) > 64 || raw != "AGCTL1 "+owner+" "+phase+" qualified=0\n" || !ValidReply(owner, []byte(raw)) {
				t.Fatal("fixed observed reply changed")
			}
			if ValidReply(owner, []byte(raw+"X")) || ValidReply("foreign", []byte(raw)) {
				t.Fatal("trailing/foreign reply admitted")
			}
		}
	}
	if _, err := Reply("frontend", "ready"); err == nil {
		t.Fatal("readiness invented")
	}
}
