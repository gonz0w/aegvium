// SPDX-License-Identifier: BSD-3-Clause
package commissionplace

import (
	"os"
	"syscall"
	"testing"
	"time"
)

type placedInfo struct {
	mode os.FileMode
	size int64
	stat syscall.Stat_t
}

func (f placedInfo) Name() string       { return "opaque" }
func (f placedInfo) Size() int64        { return f.size }
func (f placedInfo) Mode() os.FileMode  { return f.mode }
func (f placedInfo) ModTime() time.Time { return time.Time{} }
func (f placedInfo) IsDir() bool        { return f.mode.IsDir() }
func (f placedInfo) Sys() any           { return &f.stat }

func TestPlacedMetadataRequiresCurrentProtectedFile(t *testing.T) {
	good := placedInfo{mode: 0440, size: 9, stat: syscall.Stat_t{Uid: 0, Gid: 456, Nlink: 1, Mode: 0440}}
	if !placedFile(good, 0440, 9, 456) {
		t.Fatal("exact synthetic role metadata refused")
	}
	for _, change := range []func(*placedInfo){
		func(f *placedInfo) { f.stat.Uid = 456 }, func(f *placedInfo) { f.stat.Gid = 457 },
		func(f *placedInfo) { f.stat.Nlink = 2 }, func(f *placedInfo) { f.stat.Mode = 0640 },
		func(f *placedInfo) { f.stat.Mode |= syscall.S_ISUID }, func(f *placedInfo) { f.size = 10 },
		func(f *placedInfo) { f.mode = os.ModeSymlink | 0440 },
	} {
		bad := good
		change(&bad)
		if placedFile(bad, 0440, 9, 456) {
			t.Fatal("changed metadata accepted")
		}
	}
	if placedFile(nil, 0440, 9, 456) || placedFile(good, 0440, 9, -1) {
		t.Fatal("missing metadata accepted")
	}
}
