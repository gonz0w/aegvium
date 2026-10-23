// SPDX-License-Identifier: BSD-3-Clause
package commission

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// Reuse the independent C-reader literals frozen before the payload encoder,
// rather than computing an expected checkpoint with the encoder under test.
func TestPlacementInitialCheckpoint(t *testing.T) {
	for _, tc := range states {
		frame, err := hex.DecodeString(tc.frame)
		if err != nil || !InitialMatches([]byte(tc.generation), frame) {
			t.Fatal("independent initial checkpoint refused")
		}
		for i := range frame {
			changed := bytes.Clone(frame)
			changed[i] ^= 1
			if InitialMatches([]byte(tc.generation), changed) {
				t.Fatalf("changed checkpoint accepted at byte %d", i)
			}
		}
		if InitialMatches([]byte(tc.generation), frame[:127]) ||
			InitialMatches([]byte(tc.generation), append(bytes.Clone(frame), 0)) {
			t.Fatal("noncanonical checkpoint length accepted")
		}
	}
	frame, err := hex.DecodeString(states[0].frame)
	if err != nil {
		t.Fatal(err)
	}
	for _, generation := range []string{"", "00000000000000000000000000000000",
		"00000000000000000000000000000002", "0000000000000000000000000000000A",
		"000000000000000000000000000000001"} {
		if InitialMatches([]byte(generation), frame) {
			t.Fatal("invalid or mismatched generation accepted")
		}
	}
}
