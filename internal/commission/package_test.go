// SPDX-License-Identifier: BSD-3-Clause
package commission

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

// Independent contract literal: opaque values are not executable/credential
// fixtures. No package tool, child, socket, key parser or native call is used.
const packageLiteral = "AEGBIN1\ninspector 7 0101010101010101010101010101010101010101010101010101010101010101\nsupervisor 3 0202020202020202020202020202020202020202020202020202020202020202\nfrontend-owner 5 0303030303030303030303030303030303030303030303030303030303030303\n"

func TestPackageManifestFixedNamesBoundsAndCanonicalData(t *testing.T) {
	images, err := ParsePackageImages([]byte(packageLiteral))
	if err != nil || len(images) != 3 || images[0].Name != "inspector" || images[0].Size != 7 ||
		images[1].Name != "supervisor" || images[1].Digest[31] != 2 || images[2].Name != "frontend-owner" {
		t.Fatal("independent package literal refused")
	}
	for _, raw := range []string{
		"", packageLiteral + "\n", strings.TrimSuffix(packageLiteral, "\n"),
		strings.Replace(packageLiteral, "inspector 7", "inspector 07", 1),
		strings.Replace(packageLiteral, "inspector 7", "../inspector 7", 1),
		strings.Replace(packageLiteral, "inspector 7", "inspector 0", 1),
		strings.Replace(packageLiteral, "inspector 7", "inspector 67108865", 1),
		strings.Replace(packageLiteral, "supervisor 3", "supervisor 1048577", 1),
		strings.Replace(packageLiteral, "frontend-owner 5", "supervisor 5", 1),
		strings.Replace(packageLiteral, "inspector 7 ", "inspector 7  ", 1),
		strings.Replace(packageLiteral, "010101", "ABCDEF", 1),
		strings.Repeat("x", 321),
	} {
		if _, err := ParsePackageImages([]byte(raw)); err == nil {
			t.Fatal("noncanonical/foreign package member accepted")
		}
	}
	max := strings.Replace(packageLiteral, "inspector 7", "inspector 67108864", 1)
	max = strings.Replace(max, "supervisor 3", "supervisor 1048576", 1)
	max = strings.Replace(max, "frontend-owner 5", "frontend-owner 67108864", 1)
	if _, err := ParsePackageImages([]byte(max)); err != nil {
		t.Fatal("existing image boundaries changed")
	}
}

func TestProductionInputInventoryNeverFallsBack(t *testing.T) {
	base := []string{"pair.snapshot", "frontend-mode", "roles"}
	if !ProductionInputs(base, []byte("external\n")) ||
		!ProductionInputs(append(append([]string{}, base...), "frontend"), []byte("bundled\n")) {
		t.Fatal("exact source inventory refused")
	}
	for _, mode := range []string{"", "external", "bundled", "external\n\n", "BUNDLED\n"} {
		if ProductionInputs(base, []byte(mode)) {
			t.Fatal("ambiguous profile accepted")
		}
	}
	for _, names := range [][]string{base, {"pair.snapshot", "roles", "frontend-mode", "expected"},
		{"pair.snapshot", "roles", "frontend-mode", "../frontend"},
		{"pair.snapshot", "roles", "frontend-mode", "frontend-mode"}} {
		if ProductionInputs(names, []byte("bundled\n")) {
			t.Fatal("missing bundle/foreign/duplicate member accepted")
		}
	}
	if ProductionInputs(append(append([]string{}, base...), "frontend"), []byte("external\n")) {
		t.Fatal("external profile silently accepted bundled inputs")
	}
}

func TestProductionInitialFilesUseIndependentRuntimeLiterals(t *testing.T) {
	for _, tc := range states {
		d, _, pin := fixture(t)
		copy(d[8:40], tc.generation)
		files, err := InitialFiles(d, pin)
		state, e := hex.DecodeString(tc.frame)
		if err != nil || e != nil || len(files) != 5 || files[0].Name != "inspector.pin" ||
			string(files[0].Data) != imagePin+"\n" || files[1].Name != "pair.snapshot" || !bytes.Equal(files[1].Data, d) ||
			files[2].Name != "launch.intent" || string(files[2].Data) != tc.generation+"\n" ||
			files[3].Name != "security.records" || !bytes.Equal(files[3].Data, recordFixture(t, tc.generation)) ||
			files[4].Name != "launch.state" || !bytes.Equal(files[4].Data, state) {
			t.Fatal("production initializer changed independent state contract")
		}
		d[8] = 'X'
		if files[1].Data[8] == 'X' {
			t.Fatal("caller retained mutable descriptor")
		}
	}
	if _, err := InitialFiles(nil, [32]byte{}); err == nil {
		t.Fatal("missing descriptor created initial state")
	}
}
