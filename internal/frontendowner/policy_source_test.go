//go:build aegvium_frontend_source

// Adapted from private Vectivium e28959892903225887d855677c307712a59ce071; see LICENSE.Vectivium.
// No public relicensing is made.
package frontendowner

// These are pure data/time predicates. No native constructor, writer, child,
// kqueue, signal, consuming wait, credentials, TLS or RunSource is called.
import (
	"bytes"
	"testing"
	"time"
)

func literalRecord() []byte {
	r := append([]byte("AGCHECK10123456789abcdef0123456789abcdef"), bytes.Repeat([]byte{0x5e}, 32)...)
	return append(r, contractDigest[:]...)
}

func TestGenerationNames(t *testing.T) {
	if !generation("0123456789abcdef0123456789abcdef") || !generation("00000000000000000000000000000000") {
		t.Fatal("valid name")
	}
	for _, s := range []string{"", ".", "../0123456789abcdef0123456789abcdef", "0123456789ABCDEF0123456789abcdef", "0123456789abcdef0123456789abcde/"} {
		if generation(s) {
			t.Fatal("invalid name")
		}
	}
}

func TestRecordDataBoundaries(t *testing.T) {
	name := "0123456789abcdef0123456789abcdef"
	r := literalRecord()
	if !recordData(r, name) {
		t.Fatal("record data")
	}
	// All-zero is permitted generation DATA. Only exclusive protected history
	// can establish its nonreuse; lexical appearance never proves freshness.
	zero := bytes.Clone(r)
	copy(zero[8:40], "00000000000000000000000000000000")
	if !recordData(zero, "00000000000000000000000000000000") {
		t.Fatal("zero token is valid data")
	}
	for _, raw := range [][]byte{nil, r[:103], append(bytes.Clone(r), 0), bytes.Repeat([]byte{0}, 104)} {
		if recordData(raw, name) {
			t.Fatal("length/data")
		}
	}
	for _, offset := range []int{0, 8, 72, 103} {
		bad := bytes.Clone(r)
		bad[offset] ^= 1
		if recordData(bad, name) {
			t.Fatal("binding")
		}
	}
}

func TestProtectedMetadata(t *testing.T) {
	f := fileFacts{inode: 4, mode: 0100600, links: 1, size: 104}
	if !protected(f, false, 0600) {
		t.Fatal("regular")
	}
	for _, modify := range []func(*fileFacts){func(x *fileFacts) { x.uid = 1 }, func(x *fileFacts) { x.gid = 1 }, func(x *fileFacts) { x.mode = 0100660 }, func(x *fileFacts) { x.mode = 0120600 }, func(x *fileFacts) { x.links = 2 }, func(x *fileFacts) { x.inode = 0 }, func(x *fileFacts) { x.size = -1 }} {
		bad := f
		modify(&bad)
		if protected(bad, false, 0600) {
			t.Fatal("metadata")
		}
	}
	if !protected(fileFacts{inode: 3, mode: 0040700}, true, 0700) || protected(f, true, 0700) {
		t.Fatal("directory")
	}
}

func TestInventoryRecordAndCeiling(t *testing.T) {
	f := fileFacts{inode: 4, mode: 0100600, links: 1, size: 104}
	if !inventoryCapacity(0) || !inventoryCapacity(4095) || inventoryCapacity(4096) || inventoryCapacity(4097) || inventoryCapacity(-1) || !inventoryEntry("0123456789abcdef0123456789abcdef", f, literalRecord()) {
		t.Fatal("literal inventory")
	}
	f.size = 0
	if inventoryEntry("0123456789abcdef0123456789abcdef", f, nil) {
		t.Fatal("partial token must block")
	}
}

func TestIdentityIncludesMetadata(t *testing.T) {
	a := fileFacts{device: 1, inode: 2, mode: 0100600, links: 1, size: 104}
	if !sameFile(a, a) {
		t.Fatal("same")
	}
	b := a
	b.device++
	if sameFile(a, b) {
		t.Fatal("device")
	}
	b = a
	b.size++
	if sameFile(a, b) {
		t.Fatal("size")
	}
}

func TestRetirementDoesNotRenewAfterFailure(t *testing.T) {
	start := time.Unix(100, 0)
	var r retirement
	r.begin(start)
	r.begin(start.Add(1900 * time.Millisecond))
	if r.origin != start || r.killAt != start.Add(2*time.Second) || r.end != start.Add(4*time.Second) || !r.killDue(start.Add(2*time.Second)) {
		t.Fatal("renewed cancellation")
	}
}

func TestOriginalClockExactAndBackwardBoundaries(t *testing.T) {
	start := time.Unix(100, 0)
	var r retirement
	r.begin(start)
	if !r.live(start.Add(4*time.Second-time.Nanosecond)) || r.live(start.Add(4*time.Second)) || r.live(start.Add(-time.Nanosecond)) || r.killDue(start.Add(2*time.Second-time.Nanosecond)) {
		t.Fatal("clock boundary")
	}
}

func TestSignalRightsSealedAndLost(t *testing.T) {
	if !signalPhase(childOriginal) || !waitPhase(childOriginal) {
		t.Fatal("original phase policy")
	}
	for _, p := range []childPhase{childUnused, childStartAttempt, childWaitSealed, childConsumed, childLost} {
		if signalPhase(p) || waitPhase(p) {
			t.Fatal("sealed/lost phase")
		}
	}
}

func TestTerminalWaitClassification(t *testing.T) {
	for _, tc := range []struct {
		name               string
		original, observed int
		kind               waitKind
		priorUnknown       bool
		phase              childPhase
		uncertain          bool
	}{
		{"success", 41, 41, waitSucceeded, false, childConsumed, false},
		{"nonzero_or_signal_exit", 41, 41, waitExitFailure, false, childConsumed, false},
		{"prior_unknown_then_known_exit", 41, 41, waitExitFailure, true, childConsumed, true},
		{"missing_state", 41, 0, waitUnknown, false, childLost, true},
		{"mismatched_state", 41, 42, waitSucceeded, false, childLost, true},
		{"unknown_wait_with_state", 41, 41, waitUnknown, false, childConsumed, true},
		{"unrecognized_kind", 41, 41, waitKind(99), false, childConsumed, true},
		{"nonoriginal_pid", 1, 1, waitSucceeded, false, childLost, true},
	} {
		phase, uncertain := classifyTerminal(tc.original, tc.observed, tc.kind, tc.priorUnknown)
		if phase != tc.phase || uncertain != tc.uncertain || signalPhase(phase) || waitPhase(phase) {
			t.Fatalf("terminal classification %s", tc.name)
		}
	}
}
