// SPDX-License-Identifier: BSD-3-Clause
package frontendowner

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func historyLiterals(t *testing.T) (initial, active, clean [160]byte) {
	t.Helper()
	raw, e := os.ReadFile("testdata/history.json")
	if e != nil {
		t.Fatal(e)
	}
	var f struct {
		Initial string `json:"initial_clean_hex"`
		Active  string `json:"active_hex"`
		Clean   string `json:"terminal_clean_hex"`
	}
	if json.Unmarshal(raw, &f) != nil {
		t.Fatal("independent lifetime literals")
	}
	for i, s := range []string{f.Initial, f.Active, f.Clean} {
		b, e := hex.DecodeString(s)
		if e != nil || len(b) != 160 {
			t.Fatal("literal length")
		}
		switch i {
		case 0:
			copy(initial[:], b)
		case 1:
			copy(active[:], b)
		case 2:
			copy(clean[:], b)
		}
	}
	return
}
func TestFrontendLifetimeFrozenLiteralsRemainData(t *testing.T) {
	initial, active, clean := historyLiterals(t)
	if InitialHistorySource() != initial {
		t.Fatal("initial staging bytes changed")
	}
	for _, raw := range [][160]byte{initial, active, clean} {
		phase, record, ok := parseLifetime(raw)
		if !ok {
			t.Fatal("independent literal refused")
		}
		built, ok := lifetimeFrame(phase, record)
		if !ok || built != raw {
			t.Fatal("state roundtrip differs")
		}
	}
	p, r, ok := parseLifetime(initial)
	if !ok || p != 'C' || r != [104]byte{} {
		t.Fatal("initial record invents prior history")
	}
	if _, ok := lifetimeFrame('U', [104]byte{}); ok {
		t.Fatal("active child without bound tuple")
	}
	for _, phase := range []byte{0, 'A', 'X'} {
		if _, ok := lifetimeFrame(phase, r); ok {
			t.Fatal("unknown state")
		}
	}
	for _, at := range []int{0, 8, 9, 15, 16, 23, 47, 80, 119, 120, 151, 152, 159} {
		bad := active
		bad[at] ^= 1
		if _, _, ok := parseLifetime(bad); ok {
			t.Fatal("partial/drift record accepted")
		}
	}
}
func TestFrontendLifetimeRejectsHistoricalControlProfile(t *testing.T) {
	_, active, _ := historyLiterals(t)
	_, record, ok := parseLifetime(active)
	if !ok {
		t.Fatal("fixture")
	}
	old := record
	literal, e := hex.DecodeString("1d987134086420d48b300a4cfda016ffc550a0bda6a6f20c58282db1b7d42dca")
	if e != nil {
		t.Fatal(e)
	}
	copy(old[72:], literal)
	if _, ok := lifetimeFrame('U', old); ok {
		t.Fatal("CONTROL-only snapshot creates frontend child")
	}
	record[40] = 0
	for i := 41; i < 72; i++ {
		record[i] = 0
	}
	if _, ok := lifetimeFrame('C', record); ok {
		t.Fatal("missing descriptor digest accepted")
	}
}
