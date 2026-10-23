//go:build aegvium_frontend_source

// Adapted from private Vectivium e28959892903225887d855677c307712a59ce071; see LICENSE.Vectivium.
// No public relicensing is made.
package frontendowner

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// This checks record DATA only, never inventory ownership, actual generation
// consumption or a successful migration. Native history operations stay unrun.
func TestHistoricalAndDataProfileRecordsShareGenerationNamespace(t *testing.T) {
	const name = "0123456789abcdef0123456789abcdef"
	old := literalRecord()
	current := bytes.Clone(old)
	want, err := hex.DecodeString("78fc979225e6781530d791eb6156d06949a083313d02f6cf3cc0b1b68bbd0b35")
	if err != nil || !bytes.Equal(dataContractDigest[:], want) {
		t.Fatal("independent C3 literal")
	}
	copy(current[72:], want)
	if !recordData(old, name) || !recordData(current, name) {
		t.Fatal("old history must not disappear when adding C3")
	}
	if dataProfileRecord(old) || !dataProfileRecord(current) || dataProfileRecord(current[:103]) {
		t.Fatal("CONTROL-only history must never make a DATA launch profile eligible")
	}
	if string(old[8:40]) != string(current[8:40]) {
		t.Fatal("capability must not select a new generation namespace")
	}
	f := fileFacts{inode: 4, mode: 0100600, links: 1, size: 104}
	if !inventoryEntry(name, f, old) || !inventoryEntry(name, f, current) {
		t.Fatal("recognized historical record data")
	}
	unknown := bytes.Clone(current)
	unknown[72] ^= 1
	if recordData(unknown, name) || inventoryEntry(name, f, unknown) || recordData(current[:103], name) {
		t.Fatal("unknown or partial history must block")
	}
	// Both lexical records having the same name does NOT permit two files or a
	// second attempt. Only the real held-directory O_EXCL enforces that exclusion.
}
