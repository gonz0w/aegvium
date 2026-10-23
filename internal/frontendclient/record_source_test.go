//go:build aegvium_frontend_source

// Adapted from private Vectivium e28959892903225887d855677c307712a59ce071; see LICENSE.Vectivium.
// No public relicensing is made.
package frontendclient

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

func TestConfigurationRecordFrozenDataOnly(t *testing.T) {
	d, want := fixture(t)
	got, err := ConfigurationTupleSource(d, "front-a.internal.test")
	if err != nil || !bytes.Equal(got[:], want) {
		t.Fatal("independent literal104 mismatch")
	}
	for i := range d {
		d[i] = 0
	}
	if !bytes.Equal(got[:], want) {
		t.Fatal("caller storage retained")
	}
}

func TestConfigurationRecordRefusesProfilesRolesAndLengths(t *testing.T) {
	d, _ := fixture(t)
	badProfile := bytes.Clone(d)
	badProfile[46] = '2'
	for _, raw := range [][]byte{nil, d[:312], append(bytes.Clone(d), 0), make([]byte, 8193), badProfile} {
		if got, err := ConfigurationTupleSource(raw, "front-a.internal.test"); err == nil || got != [104]byte{} {
			t.Fatal("invalid configuration record")
		}
	}
	for _, role := range []string{"", "Front-a.internal.test", "outside.internal.test", "inspect.internal.test", strings.Repeat("a", 254)} {
		if got, err := ConfigurationTupleSource(d, role); err == nil || got != [104]byte{} {
			t.Fatal("invalid local role")
		}
	}
}

func TestConfigurationRecordZeroGenerationIsData(t *testing.T) {
	d, _ := fixture(t)
	copy(d[8:40], strings.Repeat("0", 32))
	want, err := hex.DecodeString("4147434845434b313030303030303030303030303030303030303030303030303030303030303030fb1cbb6303fef567b601df7016a07e456abc8749215da8783abf316981c44fb41d987134086420d48b300a4cfda016ffc550a0bda6a6f20c58282db1b7d42dca")
	if err != nil {
		t.Fatal(err)
	}
	got, err := ConfigurationTupleSource(d, "front-a.internal.test")
	if err != nil || !bytes.Equal(got[:], want) {
		t.Fatal("zero configuration record data")
	}
}
