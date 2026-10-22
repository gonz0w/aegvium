//go:build openbsd && aegvium_commission_source

// SPDX-License-Identifier: BSD-3-Clause
// Package commissionplace is the fixed install.site payload writer. It reports
// observed file equality only; the owning offline builder supplies image lifetime.
package commissionplace

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"

	"github.com/gonz0w/aegvium/internal/commission"
	"github.com/gonz0w/aegvium/internal/pairmodel"
)

var errPlacement = errors.New("offline placement incomplete")
var attempted bool
var retained []*os.File // Failed Close is never retried or turned into cleanup proof.

const payloadLimit = int64(67108864 + 32768)

func keep(f *os.File) *os.File { retained = append(retained, f); return f }

func metadata(f *os.File, mode os.FileMode, size int64) bool {
	s, err := f.Stat()
	if err != nil || !s.Mode().IsRegular() || s.Mode().Perm() != mode || s.Size() != size {
		return false
	}
	u, ok := s.Sys().(*syscall.Stat_t)
	return ok && u.Uid == 0 && u.Gid == 0 && u.Nlink == 1 && u.Mode&07777 == uint32(mode)
}

func directory(f *os.File) bool {
	s, err := f.Stat()
	if err != nil || !s.IsDir() || s.Mode().Perm()&0022 != 0 {
		return false
	}
	u, ok := s.Sys().(*syscall.Stat_t)
	return ok && u.Uid == 0 && u.Gid == 0 && u.Mode&07000 == 0
}

func lowerHex(p []byte, n int) bool {
	if len(p) != n {
		return false
	}
	for _, c := range p {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// Run is called only by the fixed, source-built install.site helper. It accepts
// no path, archive member policy, supplied freshness fact or operation provider.
// The installed/default entry is refused; this source-tagged path is unqualified.
func Run() error {
	if attempted {
		return errPlacement
	}
	attempted = true
	if os.Getuid() != 0 || os.Geteuid() != 0 || os.Getgid() != 0 || os.Getegid() != 0 {
		return errPlacement
	}
	root, err := os.OpenRoot("/")
	if err != nil {
		return errPlacement
	}
	// All destinations are literal relative names below the actual target root.
	dirs := map[string]*os.File{}
	for _, name := range []string{"var", "var/db", "usr", "usr/local", "aegvium.install"} {
		f, e := root.OpenFile(name, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
		if e != nil || !directory(keep(f)) {
			return errPlacement
		}
		named, e := root.Lstat(name)
		held, e2 := f.Stat()
		if e != nil || e2 != nil || named.Mode()&os.ModeSymlink != 0 || !os.SameFile(named, held) {
			return errPlacement
		}
		dirs[name] = f
	}
	expect, e := root.OpenFile("aegvium.install/expected", os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return errPlacement
	}
	keep(expect)
	if !metadata(expect, 0400, 163) {
		return errPlacement
	}
	want, e := io.ReadAll(io.LimitReader(expect, 164))
	if e != nil || len(want) != 163 || want[64] != '\n' || want[97] != '\n' || want[162] != '\n' ||
		!lowerHex(want[:64], 64) || !lowerHex(want[65:97], 32) || !lowerHex(want[98:162], 64) || expect.Close() != nil {
		return errPlacement
	}
	if string(want[65:97]) == "00000000000000000000000000000000" {
		return errPlacement
	}
	payload, e := root.OpenFile("aegvium.install/payload.tar", os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return errPlacement
	}
	keep(payload)
	info, e := payload.Stat()
	if e != nil || info.Size() < 1 || info.Size() > payloadLimit || !metadata(payload, 0400, info.Size()) {
		return errPlacement
	}
	h := sha256.New()
	n, e := io.Copy(h, io.LimitReader(payload, payloadLimit+1))
	if e != nil || n != info.Size() || hex.EncodeToString(h.Sum(nil)) != string(want[:64]) {
		return errPlacement
	}
	if _, e = payload.Seek(0, io.SeekStart); e != nil {
		return errPlacement
	}
	libexec, e := root.OpenFile("usr/local/libexec", os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if errors.Is(e, os.ErrNotExist) {
		if root.Mkdir("usr/local/libexec", 0755) != nil {
			return errPlacement
		}
		libexec, e = root.OpenFile("usr/local/libexec", os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
		if e == nil && libexec.Chmod(0755) != nil {
			return errPlacement
		}
		if dirs["usr/local"].Sync() != nil {
			return errPlacement
		}
	}
	if e != nil || !directory(keep(libexec)) {
		return errPlacement
	}
	dirs["usr/local/libexec"] = libexec
	for _, name := range []string{"var/db/aegvium", "usr/local/libexec/aegvium"} {
		if root.Mkdir(name, 0700) != nil {
			return errPlacement
		}
		f, e := root.OpenFile(name, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
		if e != nil || !directory(keep(f)) {
			return errPlacement
		}
		mode := os.FileMode(0700)
		if strings.HasPrefix(name, "usr/") {
			mode = 0755
		}
		if f.Chmod(mode) != nil || f.Sync() != nil {
			return errPlacement
		}
		dirs[name] = f
		parent := name[:strings.LastIndexByte(name, '/')]
		if dirs[parent].Sync() != nil {
			return errPlacement
		}
	}
	r := tar.NewReader(payload)
	names := []string{"usr/local/libexec/aegvium/inspector", "var/db/aegvium/inspector.pin", "var/db/aegvium/pair.snapshot", "var/db/aegvium/launch.intent", "var/db/aegvium/launch.state"}
	var imageDigest [32]byte
	for i, name := range names {
		header, e := r.Next()
		mode := int64(0600)
		if i == 0 {
			mode = 0555
		}
		if e != nil || header.Name != name || header.Typeflag != tar.TypeReg || header.Linkname != "" || header.Mode != mode ||
			header.Uid != 0 || header.Gid != 0 || header.Format != tar.FormatUSTAR || len(header.PAXRecords) != 0 || header.Size < 1 ||
			(i == 0 && header.Size > 67108864) || (i != 0 && header.Size > 8192) {
			return errPlacement
		}
		var data []byte
		if i != 0 {
			data, e = io.ReadAll(io.LimitReader(r, 8193))
			if e != nil || int64(len(data)) != header.Size {
				return errPlacement
			}
			switch i {
			case 1:
				if string(data) != hex.EncodeToString(imageDigest[:])+"\n" {
					return errPlacement
				}
			case 2:
				if _, e = pairmodel.Parse(data); e != nil || !bytes.Equal(data[8:40], want[65:97]) {
					return errPlacement
				}
				d := sha256.Sum256(data)
				if hex.EncodeToString(d[:]) != string(want[98:162]) {
					return errPlacement
				}
			case 3:
				if !bytes.Equal(data, append(bytes.Clone(want[65:97]), '\n')) {
					return errPlacement
				}
			case 4:
				if !commission.InitialMatches(want[65:97], data) {
					return errPlacement
				}
			}
		}
		f, e := root.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
		if e != nil {
			return errPlacement
		}
		keep(f)
		written := sha256.New()
		var copied int64
		if i == 0 {
			copied, e = io.CopyN(io.MultiWriter(f, written), r, header.Size)
		} else {
			copied, e = io.Copy(io.MultiWriter(f, written), bytes.NewReader(data))
		}
		if e != nil || copied != header.Size || f.Chown(0, 0) != nil || f.Chmod(os.FileMode(mode)) != nil || f.Sync() != nil || !metadata(f, os.FileMode(mode), header.Size) {
			return errPlacement
		}
		if _, e = f.Seek(0, io.SeekStart); e != nil {
			return errPlacement
		}
		readback := sha256.New()
		copied, e = io.Copy(readback, io.LimitReader(f, header.Size+1))
		if e != nil || copied != header.Size || !bytes.Equal(written.Sum(nil), readback.Sum(nil)) {
			return errPlacement
		}
		if i == 0 {
			copy(imageDigest[:], readback.Sum(nil))
		}
		named, e := root.Lstat(name)
		opened, e2 := f.Stat()
		if e != nil || e2 != nil || !os.SameFile(named, opened) || !metadata(f, os.FileMode(mode), header.Size) || f.Close() != nil {
			return errPlacement
		}
		parent := name[:strings.LastIndexByte(name, '/')]
		if dirs[parent].Sync() != nil {
			return errPlacement
		}
	}
	if _, e = r.Next(); e != io.EOF || payload.Close() != nil {
		return errPlacement
	}
	for _, name := range []string{"var/db/aegvium", "usr/local/libexec/aegvium", "var/db", "var", "usr/local/libexec", "usr/local", "usr", "aegvium.install"} {
		if dirs[name].Sync() != nil || dirs[name].Close() != nil {
			return errPlacement
		}
	}
	if root.Close() != nil {
		return errPlacement
	}
	line := fmt.Sprintf("AGPLACED1 %s %s %s\n", want[65:97], want[98:162], want[:64])
	if n, e := io.WriteString(os.Stdout, line); e != nil || n != len(line) {
		return errPlacement
	}
	return nil
}
