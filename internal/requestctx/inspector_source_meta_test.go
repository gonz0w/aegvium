//go:build aegvium_transport_source

// SPDX-License-Identifier: BSD-3-Clause
package requestctx

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"syscall"
	"testing"
	"time"
)

type inspectorInfoFixture struct {
	mode os.FileMode
	size int64
	stat syscall.Stat_t
}

func (f inspectorInfoFixture) Name() string       { return "opaque-fixture" }
func (f inspectorInfoFixture) Size() int64        { return f.size }
func (f inspectorInfoFixture) Mode() os.FileMode  { return f.mode }
func (f inspectorInfoFixture) ModTime() time.Time { return time.Time{} }
func (f inspectorInfoFixture) IsDir() bool        { return f.mode.IsDir() }
func (f inspectorInfoFixture) Sys() any           { return &f.stat }

func TestInspectorSourceProtectedMaterialMetadata(t *testing.T) {
	good := inspectorInfoFixture{mode: 0440, size: 16, stat: syscall.Stat_t{Uid: 0, Gid: 456, Nlink: 1, Mode: 0440}}
	if !inspectorRoleFile(good, 16, 456) {
		t.Fatal("exact protected synthetic metadata refused")
	}
	for _, change := range []func(*inspectorInfoFixture){
		func(f *inspectorInfoFixture) { f.stat.Uid = 123 },
		func(f *inspectorInfoFixture) { f.stat.Gid = 457 },
		func(f *inspectorInfoFixture) { f.stat.Nlink = 2 },
		func(f *inspectorInfoFixture) { f.stat.Mode = 0640 },
		func(f *inspectorInfoFixture) { f.stat.Mode = 0444 },
		func(f *inspectorInfoFixture) { f.stat.Mode = 0440 | syscall.S_ISUID },
		func(f *inspectorInfoFixture) { f.stat.Mode = 0440 | syscall.S_ISGID },
		func(f *inspectorInfoFixture) { f.stat.Mode = 0440 | syscall.S_ISVTX },
		func(f *inspectorInfoFixture) { f.mode = os.ModeSymlink | 0440 },
		func(f *inspectorInfoFixture) { f.mode = os.ModeDir | 0440 },
		func(f *inspectorInfoFixture) { f.size = 0 },
		func(f *inspectorInfoFixture) { f.size = 17 },
	} {
		bad := good
		change(&bad)
		if inspectorRoleFile(bad, 16, 456) {
			t.Fatal("unsafe synthetic metadata accepted")
		}
	}
	if inspectorRoleFile(nil, 16, 456) || inspectorRoleFile(good, 0, 456) ||
		inspectorRoleFile(good, 16, 0) || inspectorRoleFile(good, 16, -1) {
		t.Fatal("missing bounds/identity accepted")
	}
	for _, size := range []int64{1, 16384, 65536} {
		f := good
		f.size = size
		if !inspectorRoleFile(f, int(size), 456) || inspectorRoleFile(f, int(size)-1, 456) {
			t.Fatal("cap boundary mismatch")
		}
	}
}

func TestInspectorSourcePreparedDiagnosticLiteral(t *testing.T) {
	_, _, tuple := pairFixture(t) // Existing independent AGCHECK fixture; no credentials.
	var input [104]byte
	copy(input[:], tuple)
	frame := inspectorPreparedFrame(input)
	if !bytes.Equal(frame[:8], []byte("AGSTART1")) || !bytes.Equal(frame[8:], tuple) ||
		fmt.Sprintf("%x", sha256.Sum256(frame[:])) != "1512f8456b86df34f0780bb7b399d60440b308b2263507c64c970481cf8acbcb" {
		t.Fatal("prepared diagnostic differs from independent literal")
	}
	input[0] ^= 1
	if !bytes.Equal(frame[8:], tuple) {
		t.Fatal("diagnostic aliases input")
	}
}

func TestInspectorSourceRequiresOnePolicy(t *testing.T) {
	s, _, _ := pairFixture(t)
	pin := inspectorPolicyPin(s)
	if len(pin) != 64 {
		t.Fatal("configured profile missing")
	}
	s.context.routes["extra"] = route{pin: pin}
	if inspectorPolicyPin(s) != pin {
		t.Fatal("same profile refused")
	}
	s.context.routes["extra"] = route{pin: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}
	if inspectorPolicyPin(s) != "" {
		t.Fatal("mixed engine profiles accepted")
	}
	delete(s.context.routes, "extra")
	s.context.Retire()
	if inspectorPolicyPin(s) != "" || inspectorPolicyPin(nil) != "" {
		t.Fatal("retired/missing snapshot accepted")
	}
}
