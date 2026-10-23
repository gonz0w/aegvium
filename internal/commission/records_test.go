// SPDX-License-Identifier: BSD-3-Clause
package commission

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// Literal headers prepared with a separate Python hashlib encoder. No product
// encoder/checker output supplies these expectations; native durability is open.
var recordHeaders = []string{
	"414547534543310a410000000000000030303030303030303030303030303030303030303030303030303030303030316c62877b8a130254571b00c12c186b5a8dafe211b260f9250640bb2095eb4c8d303030303030303030303030303030303030303030303030303030303030303000000000000000000000000000000000",
	"414547534543310a41000000000000003030303030303030303030303030303030303030303030303030303030303031bc566d64c8a1bdfbf5aa1edaad7c79992983eedd6262669b002085433a55d29d303132333435363738396162636465663031323334353637383961626364656500000000000000000000000000000000",
	"414547534543310a41000000000000003030303030303030303030303030303030303030303030303030303030303031024b4dd69f9b6f8470d3fe51035a3fb7e23f1f195615f45563eb209bc2bfce41666666666666666666666666666666666666666666666666666666666666666500000000000000000000000000000000",
}

func recordFixture(t *testing.T, generation string) []byte {
	t.Helper()
	for i, tc := range states {
		if tc.generation != generation {
			continue
		}
		header, err := hex.DecodeString(recordHeaders[i])
		if err != nil || len(header) != 128 {
			t.Fatal("invalid literal record header")
		}
		return append(header, make([]byte, 8192-128)...)
	}
	t.Fatal("missing record fixture")
	return nil
}

func TestFreshRecordSegmentsAndPlacementEquality(t *testing.T) {
	for _, tc := range states {
		state, err := initialState([]byte(tc.generation))
		got := initialRecords(state)
		want := recordFixture(t, tc.generation)
		if err != nil || !bytes.Equal(got[:], want) || !InitialRecordsMatch([]byte(tc.generation), want) {
			t.Fatal("fresh records differ from literal header/empty segments")
		}
		for _, index := range []int{0, 8, 9, 16, 48, 80, 112, 128, 4096, 8191} {
			changed := bytes.Clone(want)
			changed[index] ^= 1
			if InitialRecordsMatch([]byte(tc.generation), changed) {
				t.Fatal("changed staging records accepted")
			}
		}
		if InitialRecordsMatch([]byte(tc.generation), want[:8191]) ||
			InitialRecordsMatch([]byte(tc.generation), append(bytes.Clone(want), 0)) ||
			InitialRecordsMatch([]byte("00000000000000000000000000000000"), want) {
			t.Fatal("invalid staging record bounds/generation accepted")
		}
	}
}
