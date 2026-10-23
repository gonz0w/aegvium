// SPDX-License-Identifier: BSD-3-Clause
package commission

import (
	"bytes"
	"crypto/sha256"
)

// Empty, fixed security-record segments for fresh offline staging only. The
// predecessor anchor supports any admitted first paired generation. These
// bytes establish neither fresh-image provenance nor current ownership.
func initialRecords(state [128]byte) (records [8192]byte) {
	copy(records[:8], "AEGSEC1\n")
	records[8] = 'A'
	copy(records[16:48], "00000000000000000000000000000001")
	copy(records[80:112], state[16:48])
	hash := sha256.New()
	_, _ = hash.Write(records[:48])
	_, _ = hash.Write(records[80:4096])
	copy(records[48:80], hash.Sum(nil))
	return records
}

// InitialRecordsMatch checks staging equality, never a live record reset or
// retention/cleanup authority. Only the existing fresh placement consumes it.
func InitialRecordsMatch(generation, records []byte) bool {
	state, err := initialState(generation)
	want := initialRecords(state)
	return err == nil && bytes.Equal(records, want[:])
}
