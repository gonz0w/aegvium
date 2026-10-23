//go:build aegvium_frontend_source

// Adapted from private Vectivium e28959892903225887d855677c307712a59ce071; see LICENSE.Vectivium.
// No public relicensing is made.
package frontendowner

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"time"
)

var ErrUnavailable = errors.New("startup owner source unavailable")

// RunSource is deliberately closed before all root, filesystem and process
// effects. Source-only configuration/composition never enables native admission.
// No caller switch, callback, record, handle or receipt can open this entry.
func RunSource() error { return runQualifiedSource() }

const historyLimit = 4096

var contractDigest = [32]byte{0x1d, 0x98, 0x71, 0x34, 0x08, 0x64, 0x20, 0xd4, 0x8b, 0x30, 0x0a, 0x4c, 0xfd, 0xa0, 0x16, 0xff, 0xc5, 0x50, 0xa0, 0xbd, 0xa6, 0xa6, 0xf2, 0x0c, 0x58, 0x28, 0x2d, 0xb1, 0xb7, 0xd4, 0x2d, 0xca}

var dataContractDigest = sha256.Sum256([]byte("M2-H1/3"))

func generation(s string) bool {
	if len(s) != 32 {
		return false
	}
	for _, c := range []byte(s) {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func recordData(raw []byte, name string) bool {
	return generation(name) && len(raw) == 104 && string(raw[:8]) == "AGCHECK1" &&
		string(raw[8:40]) == name && !bytes.Equal(raw[40:72], make([]byte, 32)) &&
		(bytes.Equal(raw[72:], contractDigest[:]) || bytes.Equal(raw[72:], dataContractDigest[:]))
}

// Profile eligibility is only a necessary local configuration condition. It
// supplies no DATA/engine/containment readiness or actual frontend authority.
func dataProfileRecord(raw []byte) bool {
	return len(raw) == 104 && recordData(raw, string(raw[8:40])) && bytes.Equal(raw[72:], dataContractDigest[:])
}

type fileFacts struct {
	device, inode                                      uint64
	mode                                               uint32
	uid, gid                                           uint32
	links                                              uint64
	size                                               int64
	modifiedSec, modifiedNsec, changedSec, changedNsec int64
}

func protected(f fileFacts, directory bool, perm uint32) bool {
	typeBits := uint32(0100000)
	if directory {
		typeBits = 0040000
	}
	return f.inode != 0 && f.uid == 0 && f.gid == 0 && f.mode == typeBits|perm &&
		(directory || f.links == 1) && f.size >= 0
}

func sameFile(a, b fileFacts) bool {
	return a == b
}

func inventoryCapacity(count int) bool { return count >= 0 && count < historyLimit }

func inventoryEntry(name string, f fileFacts, raw []byte) bool {
	return protected(f, false, 0600) && f.size == 104 && recordData(raw, name)
}

func before(now, origin, end time.Time) bool {
	return !origin.IsZero() && !now.Before(origin) && now.Before(end)
}

// A single cancellation origin survives every error path. This is policy data,
// not a process handle or a substitute for the actual original child's owner.
type retirement struct {
	origin, killAt, end time.Time
}

func (r *retirement) begin(now time.Time) {
	if !r.origin.IsZero() && !now.Before(r.origin) {
		return
	}
	r.origin, r.killAt, r.end = now, now.Add(2*time.Second), now.Add(4*time.Second)
}

// observe is applied on every accepted stop, including during retirement.
// Receiving an older epoch after cleanup began may make the target immediately
// late; neither a later epoch nor continued physical cleanup grants new grace.
func (r *retirement) observe(origin, now time.Time) bool {
	r.begin(origin)
	return !r.live(now)
}

func (r retirement) live(now time.Time) bool { return before(now, r.origin, r.end) }
func (r retirement) killDue(now time.Time) bool {
	return !r.origin.IsZero() && !now.Before(r.killAt)
}

type childPhase uint8

const (
	childUnused childPhase = iota
	childStartAttempt
	childOriginal
	childWaitSealed
	childConsumed
	childLost
)

func signalPhase(p childPhase) bool { return p == childOriginal }
func waitPhase(p childPhase) bool   { return p == childOriginal }

// Terminal policy consumes no process itself. The native leaf supplies only
// facts from its one actual Cmd.Wait, never caller proof objects or observers.
type waitKind uint8

const (
	waitUnknown waitKind = iota
	waitSucceeded
	waitExitFailure
)

func classifyTerminal(original, observed int, kind waitKind, priorUnknown bool) (childPhase, bool) {
	if original <= 1 || observed != original {
		return childLost, true
	}
	return childConsumed, priorUnknown || kind != waitSucceeded && kind != waitExitFailure
}
