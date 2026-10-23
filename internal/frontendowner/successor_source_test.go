//go:build aegvium_frontend_source

// SPDX-License-Identifier: BSD-3-Clause
package frontendowner

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

type successorLiteral struct {
	Old    string `json:"old_generation"`
	Next   string `json:"next_generation"`
	Digest string `json:"next_descriptor_sha256"`
	Clean  string `json:"clean_checkpoint_hex"`
}

func successorFixture(t *testing.T) (old, next, backend, nextBackend []byte, record [104]byte, l successorLiteral) {
	t.Helper()
	read := func(name string, out any) {
		raw, e := os.ReadFile(name)
		if e != nil || json.Unmarshal(raw, out) != nil {
			t.Fatal("public fixture")
		}
	}
	var p struct {
		Row struct {
			Descriptor string `json:"descriptor_hex"`
			Record     string `json:"prepared_hex"`
		} `json:"same_address_distinct_ports"`
	}
	read("../requestctx/testdata/pair2_prepared.json", &p)
	var b struct {
		Backend string `json:"backend_hex"`
	}
	read("../backendconfig/testdata/binding.json", &b)
	read("testdata/successor.json", &l)
	decode := func(s string) []byte {
		v, e := hex.DecodeString(s)
		if e != nil {
			t.Fatal("public hex")
		}
		return v
	}
	old = decode(p.Row.Descriptor)
	copy(record[:], decode(p.Row.Record))
	backend = decode(b.Backend)
	// Adapt only the independent old AGPAIR1 backend binding to the frozen AGPAIR2
	// fixture; body/roles/addresses remain the independent backend literal.
	sum := sha256.Sum256(old)
	copy(backend[40:72], sum[:])
	next = bytes.Clone(old)
	copy(next[8:40], l.Next)
	digest := sha256.Sum256(next)
	if hex.EncodeToString(digest[:]) != l.Digest {
		t.Fatal("independent successor literal changed")
	}
	nextBackend = bytes.Clone(backend)
	copy(nextBackend[8:40], l.Next)
	copy(nextBackend[40:72], digest[:])
	return
}
func TestNormalSuccessorChangesOnlyExactNextBinding(t *testing.T) {
	old, next, b, nb, record, _ := successorFixture(t)
	keep := [][]byte{bytes.Clone(old), bytes.Clone(next), bytes.Clone(b), bytes.Clone(nb)}
	if !successorData(old, next, b, nb, record) {
		t.Fatal("exact generation-only successor refused")
	}
	for i, raw := range [][]byte{old, next, b, nb} {
		if !bytes.Equal(raw, keep[i]) {
			t.Fatal("input mutated")
		}
	}
}

// Frozen before the in-memory derivation implementation. The existing public
// successor literal fixes g+1 and its full digest independently of the producer.
func TestNormalSuccessorDerivesExactDetachedBindings(t *testing.T) {
	old, next, backend, nextBackend, record, _ := successorFixture(t)
	keepOld, keepBackend := bytes.Clone(old), bytes.Clone(backend)
	got, gotBackend, err := deriveSuccessor(old, backend, record)
	if err != nil || !bytes.Equal(got, next) || !bytes.Equal(gotBackend, nextBackend) {
		t.Fatal("derived bytes differ from fixed successor literals")
	}
	if !bytes.Equal(old, keepOld) || !bytes.Equal(backend, keepBackend) {
		t.Fatal("derivation changed current inputs")
	}
	got[0] ^= 1
	gotBackend[0] ^= 1
	if !bytes.Equal(old, keepOld) || !bytes.Equal(backend, keepBackend) {
		t.Fatal("derived buffers alias current inputs")
	}
}

func TestNormalSuccessorDerivationRejectsInvalidCurrentInputs(t *testing.T) {
	old, _, backend, _, record, _ := successorFixture(t)
	refuse := func(name string, d, b []byte, r [104]byte) {
		t.Helper()
		dKeep, bKeep := bytes.Clone(d), bytes.Clone(b)
		next, nextBackend, err := deriveSuccessor(d, b, r)
		if err == nil || next != nil || nextBackend != nil || !bytes.Equal(d, dKeep) || !bytes.Equal(b, bKeep) {
			t.Fatalf("%s returned candidate or changed input", name)
		}
	}
	for _, d := range [][]byte{nil, old[:47], append(bytes.Clone(old), 0), bytes.Repeat([]byte{'x'}, 8193)} {
		refuse("invalid descriptor", d, backend, record)
	}
	for _, b := range [][]byte{nil, backend[:71], append(bytes.Clone(backend), 0), bytes.Repeat([]byte{'x'}, 8193)} {
		refuse("invalid backend", old, b, record)
	}
	for _, at := range []int{0, 8, 40, 72} {
		b := bytes.Clone(backend)
		b[at] ^= 1
		refuse("invalid backend binding or body", old, b, record)
	}
	for _, at := range []int{0, 8, 40, 72} {
		r := record
		r[at] ^= 1
		refuse("foreign consumed tuple", old, backend, r)
	}
	for _, g := range []string{strings.Repeat("0", 32), strings.Repeat("f", 32)} {
		d, b, r := bytes.Clone(old), bytes.Clone(backend), record
		copy(d[8:40], g)
		sum := sha256.Sum256(d)
		copy(b[8:40], g)
		copy(b[40:72], sum[:])
		copy(r[8:40], g)
		copy(r[40:72], sum[:])
		refuse("zero or wrapped generation", d, b, r)
	}
}

func TestNormalSuccessorRefusesReplaySkipZeroAndWrap(t *testing.T) {
	old, next, b, nb, record, l := successorFixture(t)
	for _, g := range []string{l.Old, "0123456789abcdef0123456789abcdf1", strings.Repeat("0", 32)} {
		d := bytes.Clone(next)
		copy(d[8:40], g)
		n := bytes.Clone(nb)
		copy(n[8:40], g)
		sum := sha256.Sum256(d)
		copy(n[40:72], sum[:])
		if successorData(old, d, b, n, record) {
			t.Fatal("replay/skipped/zero accepted")
		}
	}
	for _, g := range []string{strings.Repeat("f", 32), strings.Repeat("0", 32), "not-generation", strings.Repeat("G", 32)} {
		if _, ok := nextGeneration(g); ok {
			t.Fatal("invalid/wrapped generation")
		}
	}
	for _, row := range [][2]string{{l.Old, l.Next}, {"000000000000000000000000ffffffff", "00000000000000000000000100000000"}} {
		got, ok := nextGeneration(row[0])
		if !ok || got != row[1] {
			t.Fatal("fixed carry")
		}
	}
}
func TestNormalSuccessorRefusesMixedOrChangedMaterial(t *testing.T) {
	old, next, b, nb, record, _ := successorFixture(t)
	for _, at := range []int{40, 50, len(next) - 1} {
		n := bytes.Clone(next)
		n[at] ^= 1
		if successorData(old, n, b, nb, record) {
			t.Fatal("descriptor tail changed")
		}
	}
	for _, at := range []int{8, 40, 72, len(nb) - 1} {
		n := bytes.Clone(nb)
		n[at] ^= 1
		if successorData(old, next, b, n, record) {
			t.Fatal("backend binding/role change")
		}
	}
	for _, at := range []int{8, 40, 72} {
		r := record
		r[at] ^= 1
		if successorData(old, next, b, nb, r) {
			t.Fatal("foreign prior tuple")
		}
	}
	for _, raw := range [][]byte{nil, next[:47], append(bytes.Clone(next), 0)} {
		if successorData(old, raw, b, nb, record) {
			t.Fatal("partial/extended descriptor")
		}
	}
	if successorData(old, next, b, b, record) {
		t.Fatal("stale backend accepted")
	}
}
func TestNormalSuccessorIntentFencesEveryIncompletePublication(t *testing.T) {
	_, _, _, _, _, l := successorFixture(t)
	if !launchIntent([]byte(l.Next+"\n"), l.Next) {
		t.Fatal("exact final intent")
	}
	for _, raw := range []string{"", l.Old + "\n", l.Next, l.Next + "\nX", l.Next + "\r\n", strings.Repeat("0", 32) + "\n", l.Next[:16] + strings.Repeat("0", 16) + "\n"} {
		if launchIntent([]byte(raw), l.Next) {
			t.Fatal("incomplete/foreign intent")
		}
	}
	if launchIntent([]byte(strings.Repeat("0", 32)+"\n"), strings.Repeat("0", 32)) {
		t.Fatal("zero is not launchable")
	}
}
func TestNormalSuccessorRequiresCanonicalNonzeroInspectorClean(t *testing.T) {
	_, _, _, _, _, l := successorFixture(t)
	raw, e := hex.DecodeString(l.Clean)
	if e != nil || !inspectorClean(raw, l.Old) {
		t.Fatal("independent C literal")
	}
	if inspectorClean(raw, l.Next) || inspectorClean(raw[:127], l.Old) || inspectorClean(append(bytes.Clone(raw), 0), l.Old) {
		t.Fatal("wrong/partial clean")
	}
	for _, at := range []int{0, 8, 9, 16, 48, 80, 127} {
		bad := bytes.Clone(raw)
		bad[at] ^= 1
		if inspectorClean(bad, l.Old) {
			t.Fatal("corrupt/unclean accepted")
		}
	}
	bad := bytes.Clone(raw)
	bad[8] = 'U'
	sum := sha256.Sum256(append(bytes.Clone(bad[:48]), bad[80:]...))
	copy(bad[48:80], sum[:])
	if inspectorClean(bad, l.Old) {
		t.Fatal("valid U was cleaned")
	}
}
func TestNormalSuccessorPreservesProtectedReplacementIdentity(t *testing.T) {
	a := fileFacts{device: 1, inode: 2, mode: 0100440, uid: 0, gid: 32767, links: 1, size: 213, modifiedSec: 10, changedSec: 11}
	if !successorRoleFacts(a, 32767) || successorRoleFacts(a, 0) || successorRoleFacts(a, 1) {
		t.Fatal("role placement")
	}
	b := a
	b.modifiedSec++
	b.changedSec++
	if !successorSamePlacement(a, b) {
		t.Fatal("own write times allowed")
	}
	for _, bad := range []fileFacts{{device: 2, inode: 2, mode: a.mode, gid: a.gid, links: 1, size: 213}, {device: 1, inode: 3, mode: a.mode, gid: a.gid, links: 1, size: 213}, {device: 1, inode: 2, mode: 0100640, gid: a.gid, links: 1, size: 213}, {device: 1, inode: 2, mode: a.mode, gid: 1, links: 1, size: 213}, {device: 1, inode: 2, mode: a.mode, gid: a.gid, links: 2, size: 213}, {device: 1, inode: 2, mode: a.mode, gid: a.gid, links: 1, size: 212}} {
		if successorSamePlacement(a, bad) {
			t.Fatal("replacement identity drift")
		}
	}
}
