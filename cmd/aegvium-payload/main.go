// SPDX-License-Identifier: BSD-3-Clause
// aegvium-payload assembles offline staging data; it never installs or launches.
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"syscall"

	"github.com/gonz0w/aegvium/internal/commission"
	"github.com/gonz0w/aegvium/internal/pairmodel"
)

func main() {
	if err := run(); err != nil {
		// Fixed message only: no paths, descriptors, image bytes or raw errors.
		fmt.Fprintln(os.Stderr, "offline payload failed; retain incomplete output and do not install it")
		os.Exit(1)
	}
}

func run() error {
	pairPath := flag.String("pair", "", "public AGPAIR1 descriptor")
	imagePath := flag.String("inspector", "", "reviewed inspector artifact")
	pin := flag.String("sha256", "", "expected inspector SHA256 (equality only)")
	outputPath := flag.String("output", "", "new staging archive; never an installed path")
	flag.Parse()
	if flag.NArg() != 0 || *pairPath == "" || *imagePath == "" || *outputPath == "" || len(*pin) != 64 {
		return commission.ErrPayload
	}
	digest, err := hex.DecodeString(*pin)
	if err != nil || hex.EncodeToString(digest) != *pin {
		return commission.ErrPayload
	}
	var expected [32]byte
	copy(expected[:], digest)
	pair, err := openInput(*pairPath)
	if err != nil {
		return commission.ErrPayload
	}
	info, statErr := pair.Stat()
	if statErr != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 8192 {
		_ = pair.Close()
		return commission.ErrPayload
	}
	descriptor, readErr := io.ReadAll(io.LimitReader(pair, 8193))
	closeErr := pair.Close()
	if readErr != nil || closeErr != nil || int64(len(descriptor)) != info.Size() {
		return commission.ErrPayload
	}
	if _, err := pairmodel.Parse(descriptor); err != nil || string(descriptor[8:40]) == "00000000000000000000000000000000" {
		return commission.ErrPayload
	}
	image, err := openInput(*imagePath)
	if err != nil {
		return commission.ErrPayload
	}
	info, err = image.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > commission.MaxImageBytes {
		_ = image.Close()
		return commission.ErrPayload
	}
	// No truncation, replacement, chown, extraction, target-root writes or cleanup.
	// An existing file/symlink refuses. A failed new archive is retained as-is.
	output, err := os.OpenFile(*outputPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		_ = image.Close()
		return commission.ErrPayload
	}
	writeErr := commission.Write(output, descriptor, image, info.Size(), expected)
	imageCloseErr := image.Close()
	if writeErr != nil || imageCloseErr != nil {
		_ = output.Close()
		return commission.ErrPayload
	}
	syncErr := output.Sync()
	outputCloseErr := output.Close()
	if syncErr != nil || outputCloseErr != nil {
		return commission.ErrPayload
	}
	return nil
}

func openInput(path string) (*os.File, error) {
	// Only regular files pass the caller's Stat check. Nonblocking open avoids
	// waiting on a FIFO before that check; final symlinks are not followed.
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
}
