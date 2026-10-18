// SPDX-License-Identifier: BSD-3-Clause
package spike

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestLabFileRegular(t *testing.T) {
	for _, c := range []struct {
		name, text string
		accepted   bool
	}{{"empty", "", true}, {"below", "abc", true}, {"exact", "12345678", true}, {"above", "123456789", false}} {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "input")
			if err := os.WriteFile(path, []byte(c.text), 0600); err != nil {
				t.Fatal(err)
			}
			data, err := ReadLabFile(path, 8)
			if c.accepted {
				if err != nil || string(data) != c.text {
					t.Fatal("regular input changed or rejected")
				}
			} else if err == nil || data != nil {
				t.Fatal("oversized input admitted")
			}
		})
	}
}

func TestLabFileSpecial(t *testing.T) {
	for _, name := range []string{"missing", "symlink", "directory", "fifo"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "input")
			switch name {
			case "symlink":
				target := filepath.Join(dir, "target")
				if err := os.WriteFile(target, []byte("owned"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := syscall.Mkfifo(path, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if data, err := ReadLabFile(path, 8); err == nil || data != nil {
				t.Fatal("nonregular or missing input admitted")
			}
		})
	}
}

type labFileInfo struct {
	mode os.FileMode
	size int64
}

func (i labFileInfo) Name() string       { return "owned" }
func (i labFileInfo) Size() int64        { return i.size }
func (i labFileInfo) Mode() os.FileMode  { return i.mode }
func (i labFileInfo) ModTime() time.Time { return time.Time{} }
func (i labFileInfo) IsDir() bool        { return i.mode.IsDir() }
func (i labFileInfo) Sys() any           { return nil }

type labFakeInputFile struct {
	reader               io.Reader
	info                 labFileInfo
	statErr, closeErr    error
	reads, bytes, closed int
}

func (f *labFakeInputFile) Read(p []byte) (int, error) {
	f.reads++
	n, e := f.reader.Read(p)
	f.bytes += n
	return n, e
}
func (f *labFakeInputFile) Stat() (os.FileInfo, error) { return f.info, f.statErr }
func (f *labFakeInputFile) Close() error               { f.closed++; return f.closeErr }

type labFileReadFailure struct{ err error }

func (r labFileReadFailure) Read(p []byte) (int, error) { p[0] = 'x'; return 1, r.err }

func TestLabFileDescriptor(t *testing.T) {
	readErr, statErr, closeErr := errors.New("owned read failure"), errors.New("owned stat failure"), errors.New("owned close failure")
	for _, name := range []string{"regular", "nonregular", "oversized-stat", "stat-error", "read-error", "close-error", "joined-errors", "growth"} {
		t.Run(name, func(t *testing.T) {
			f := &labFakeInputFile{reader: strings.NewReader("ok"), info: labFileInfo{size: 2}}
			switch name {
			case "nonregular":
				f.info = labFileInfo{mode: os.ModeNamedPipe}
			case "oversized-stat":
				f.info.size = 9
			case "stat-error":
				f.statErr = statErr
				f.closeErr = closeErr
			case "read-error":
				f.reader = labFileReadFailure{readErr}
			case "close-error":
				f.closeErr = closeErr
			case "joined-errors":
				f.reader = labFileReadFailure{readErr}
				f.closeErr = closeErr
			case "growth":
				f.info.size = 1
				f.reader = strings.NewReader(strings.Repeat("x", 64))
			}
			data, err := readLabFile("owned", 8, func(_ string, _ int) (labInputFile, error) {
				return f, nil
			})
			if f.closed != 1 {
				t.Fatal("descriptor not closed exactly once")
			}
			if name == "regular" {
				if err != nil || !bytes.Equal(data, []byte("ok")) {
					t.Fatal("regular descriptor failed")
				}
				return
			}
			if err == nil || data != nil {
				t.Fatal("failed descriptor returned usable bytes")
			}
			if (name == "nonregular" || name == "oversized-stat" || name == "stat-error") && f.reads != 0 {
				t.Fatal("read before descriptor admission")
			}
			if name == "growth" && f.bytes != 9 {
				t.Fatal("actual source read exceeded cap plus one")
			}
			if f.statErr != nil && !errors.Is(err, statErr) {
				t.Fatal("stat cause lost")
			}
			if (name == "read-error" || name == "joined-errors") && !errors.Is(err, readErr) {
				t.Fatal("read cause lost")
			}
			if f.closeErr != nil && !errors.Is(err, closeErr) {
				t.Fatal("close cause lost")
			}
		})
	}
}

func TestLabFileLimits(t *testing.T) {
	for name, limit := range map[string]int{"negative": -1, "zero": 0, "overflow": int(^uint(0) >> 1)} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "input")
			if err := os.WriteFile(path, []byte("owned input"), 0600); err != nil {
				t.Fatal(err)
			}
			if data, err := ReadLabFile(path, limit); err == nil || data != nil {
				t.Fatal("public reader accepted invalid bound")
			}
			opened := false
			data, err := readLabFile("owned", limit, func(string, int) (labInputFile, error) { opened = true; return nil, errors.New("unexpected open") })
			if err == nil || data != nil || opened {
				t.Fatal("invalid bound reached opener")
			}
		})
	}
}

func TestLabFileOpenFailure(t *testing.T) {
	cause := errors.New("owned open failure")
	calls := 0
	data, err := readLabFile("owned", 8, func(string, int) (labInputFile, error) { calls++; return nil, cause })
	if data != nil || !errors.Is(err, cause) || calls != 1 {
		t.Fatal("open failure ownership changed")
	}
}
