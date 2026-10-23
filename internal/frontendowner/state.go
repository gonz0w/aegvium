// SPDX-License-Identifier: BSD-3-Clause
package frontendowner

import (
	"bytes"
	"crypto/sha256"
)

// InitialHistorySource returns unbound staging data only. Only the already
// owning first-image writer may place it in a genuinely fresh target. It cannot
// reset/adopt an image or prove freshness, physical cleanup or launch authority.
func InitialHistorySource() [160]byte {
	raw, _ := lifetimeFrame('C', [104]byte{})
	return raw
}

func lifetimeFrame(phase byte, record [104]byte) (raw [160]byte, ok bool) {
	blank := record == [104]byte{}
	if phase != 'C' && phase != 'U' || phase == 'U' && blank || !blank && !lifetimeDataRecord(record[:]) {
		return raw, false
	}
	copy(raw[:8], "AEGFRN1\n")
	raw[8] = phase
	copy(raw[16:120], record[:])
	digest := sha256.New()
	_, _ = digest.Write(raw[:120])
	_, _ = digest.Write(raw[152:])
	copy(raw[120:152], digest.Sum(nil))
	return raw, true
}

func parseLifetime(raw [160]byte) (phase byte, record [104]byte, ok bool) {
	if string(raw[:8]) != "AEGFRN1\n" || !bytes.Equal(raw[9:16], make([]byte, 7)) || !bytes.Equal(raw[152:], make([]byte, 8)) {
		return 0, record, false
	}
	phase = raw[8]
	copy(record[:], raw[16:120])
	want, valid := lifetimeFrame(phase, record)
	return phase, record, valid && want == raw
}

// Historical configuration bytes are not a consumed/current-owner capability.
// This history belongs only to the bundled DATA profile; CONTROL-only snapshots
// remain compatible with the independent client, never a frontend launch.
func lifetimeDataRecord(raw []byte) bool {
	if len(raw) != 104 || string(raw[:8]) != "AGCHECK1" {
		return false
	}
	for _, c := range raw[8:40] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	profile := sha256.Sum256([]byte("M2-H1/3"))
	return !bytes.Equal(raw[40:72], make([]byte, 32)) && bytes.Equal(raw[72:], profile[:])
}
