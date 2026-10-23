// SPDX-License-Identifier: BSD-3-Clause
// Package commission prepares offline payload data. It cannot commission an
// image, establish freshness, install files or grant launch/cleanup authority.
package commission

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"time"

	"github.com/gonz0w/aegvium/internal/pairmodel"
)

const MaxImageBytes int64 = 67108864

var ErrPayload = errors.New("invalid or incomplete offline payload")

// Write streams one payload to out. A successful archive is still only staging
// data: its consumer must establish fresh, never-started paired-image provenance.
// Any failure invalidates the entire output, which must not be installed. The
// supplied digest is equality data, not release authenticity or custody proof.
func Write(out io.Writer, descriptor []byte, image io.Reader, imageBytes int64, expected [32]byte) error {
	if out == nil || image == nil || imageBytes < 1 || imageBytes > MaxImageBytes {
		return ErrPayload
	}
	parsed, err := pairmodel.Parse(descriptor)
	if err != nil {
		return ErrPayload
	}
	descriptor = parsed.Bytes() // Detached validated AGPAIR1/2, same8192 cap.
	state, err := initialState(descriptor[8:40])
	if err != nil {
		return ErrPayload
	}
	records := initialRecords(state)
	tw := tar.NewWriter(exactOutput{out})
	header := func(name string, mode, size int64) error {
		return tw.WriteHeader(&tar.Header{
			Name: name, Mode: mode, Size: size, Typeflag: tar.TypeReg,
			Uid: 0, Gid: 0, Uname: "root", Gname: "wheel",
			ModTime: time.Unix(0, 0), Format: tar.FormatUSTAR,
		})
	}
	// No initial clean checkpoint is emitted before the complete image and its
	// expected digest match. Do not close/finalize an archive on any error.
	if header("usr/local/libexec/aegvium/inspector", 0555, imageBytes) != nil {
		return ErrPayload
	}
	hash := sha256.New()
	if n, err := io.CopyN(io.MultiWriter(tw, hash), image, imageBytes); err != nil || n != imageBytes {
		return ErrPayload
	}
	var extra [1]byte
	if n, err := image.Read(extra[:]); n != 0 || err != io.EOF || !bytes.Equal(hash.Sum(nil), expected[:]) {
		return ErrPayload
	}
	pin := append([]byte(hex.EncodeToString(expected[:])), '\n')
	intent := append(bytes.Clone(descriptor[8:40]), '\n')
	for _, file := range []struct {
		name string
		data []byte
	}{
		{"var/db/aegvium/inspector.pin", pin},
		{"var/db/aegvium/pair.snapshot", descriptor},
		{"var/db/aegvium/launch.intent", intent},
		{"var/db/aegvium/security.records", records[:]},
		{"var/db/aegvium/launch.state", state[:]},
	} {
		if header(file.name, 0600, int64(len(file.data))) != nil {
			return ErrPayload
		}
		if n, err := tw.Write(file.data); err != nil || n != len(file.data) {
			return ErrPayload
		}
	}
	if tw.Close() != nil {
		return ErrPayload
	}
	return nil
}

// archive/tar relies on io.Writer's contract; reject a short successful write
// explicitly so even header/final-block truncation cannot report success.
type exactOutput struct{ io.Writer }

func (w exactOutput) Write(p []byte) (int, error) {
	n, err := w.Writer.Write(p)
	if n < 0 || n > len(p) {
		return 0, ErrPayload
	}
	if n != len(p) && err == nil {
		err = io.ErrShortWrite
	}
	return n, err
}

// Initial C is the immediate predecessor of the first paired launch generation.
// This encoder is not a normal-clean writer and has no installed-state I/O.
func initialState(generation []byte) (state [128]byte, err error) {
	if len(generation) != 32 {
		return state, ErrPayload
	}
	previous := bytes.Clone(generation)
	for _, c := range previous {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return state, ErrPayload
		}
	}
	borrow := true
	for i := len(previous) - 1; i >= 0 && borrow; i-- {
		switch previous[i] {
		case '0':
			previous[i] = 'f'
		case 'a':
			previous[i] = '9'
			borrow = false
		default:
			previous[i]--
			borrow = false
		}
	}
	if borrow {
		return state, ErrPayload // Zero cannot have an initial predecessor.
	}
	copy(state[:8], "AEGOWN1\n")
	state[8] = 'C'
	copy(state[16:48], previous)
	hash := sha256.New()
	_, _ = hash.Write(state[:48])
	_, _ = hash.Write(state[80:])
	copy(state[48:80], hash.Sum(nil))
	return state, nil
}
