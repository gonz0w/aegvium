//go:build openbsd && aegvium_commission_source

// SPDX-License-Identifier: BSD-3-Clause
package commissionplace

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"syscall"

	"github.com/gonz0w/aegvium/internal/commission"
)

// Neither argv, environment, staging bytes nor a supplied receipt enables this
// gate. Boot's actual fresh-target custody and exact8.0 native acceptance remain
// required. This initializer is not a fresh-image or authority constructor.
const nativeProductionCommissionQualified = false

func RunProduction() error {
	if !nativeProductionCommissionQualified {
		return errPlacement
	}
	return runProduction()
}

func packageImages(root *os.Root) ([]commission.PackageImage, []byte, error) {
	raw, err := sourceBytes(root, "usr/local/share/aegvium/package.images", 320, 0444)
	if err != nil {
		return nil, nil, errPlacement
	}
	images, err := commission.ParsePackageImages(raw)
	if err != nil {
		return nil, nil, errPlacement
	}
	for _, image := range images {
		data, err := sourceBytes(root, "usr/local/libexec/aegvium/"+image.Name, image.Size, 0555)
		if err != nil || int64(len(data)) != image.Size || sha256.Sum256(data) != image.Digest {
			return nil, nil, errPlacement
		}
	}
	return images, raw, nil
}

// Runs only inside the actual never-started target under Boot's continuous
// exclusive lifetime. Root and file equality cannot establish that prerequisite.
// No root selector, callback, archive operation, raw command or reset is exposed.
func runProduction() error {
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
	dirs := map[string]*os.File{}
	for _, name := range []string{"var", "var/db", "usr", "usr/local", "usr/local/libexec", "usr/local/libexec/aegvium", "usr/local/share", "usr/local/share/aegvium", "etc", "aegvium.install"} {
		f, e := root.OpenFile(name, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
		if e != nil || !directory(keep(f)) {
			return errPlacement
		}
		named, e := root.Lstat(name)
		held, e2 := f.Stat()
		if e != nil || e2 != nil || !os.SameFile(named, held) || named.Mode()&os.ModeSymlink != 0 ||
			name == "aegvium.install" && held.Mode().Perm() != 0700 {
			return errPlacement
		}
		dirs[name] = f
	}
	images, manifest, err := packageImages(root)
	if err != nil {
		return errPlacement
	}
	descriptor, err := sourceBytes(root, "aegvium.install/pair.snapshot", 8192, 0400)
	if err != nil {
		return errPlacement
	}
	initial, err := commission.InitialFiles(descriptor, images[0].Digest)
	if err != nil {
		return errPlacement
	}
	mode, err := sourceBytes(root, "aegvium.install/frontend-mode", 9, 0400)
	if err != nil {
		return errPlacement
	}
	entries, err := dirs["aegvium.install"].ReadDir(5)
	if err != nil {
		return errPlacement
	}
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	if !commission.ProductionInputs(names, mode) {
		return errPlacement
	}
	plan, material, err := readRoleMaterials(root, dirs, descriptor)
	if err != nil {
		return errPlacement
	}
	// Exclusive creation is a collision check, never a proof of image freshness.
	// No existing namespace/account is repaired or adopted; partial state remains.
	for _, name := range []string{"var/db/aegvium", "etc/aegvium"} {
		if _, err := root.Lstat(name); !os.IsNotExist(err) {
			return errPlacement
		}
	}
	if makeDirectory(root, dirs, "var/db/aegvium", 0700) != nil {
		return errPlacement
	}
	for _, file := range initial {
		if installBytes(root, dirs, "var/db/aegvium/"+file.Name, file.Data, 0600, 0) != nil {
			return errPlacement
		}
	}
	gid, err := dedicatedAccount(root)
	if err != nil || makeDirectory(root, dirs, "etc/aegvium", 0755) != nil ||
		makeDirectory(root, dirs, "etc/aegvium/inspector", 0755) != nil {
		return errPlacement
	}
	for i, file := range plan {
		if installBytes(root, dirs, "etc/aegvium/inspector/"+file.Name, material[i], 0440, gid) != nil {
			return errPlacement
		}
	}
	if placeFrontendFrom(root, dirs, descriptor, true) != nil {
		return errPlacement
	}
	_, currentManifest, err := packageImages(root)
	if err != nil || !bytes.Equal(currentManifest, manifest) {
		return errPlacement
	}
	for _, name := range []string{"etc/aegvium/inspector", "etc/aegvium", "aegvium.install/roles", "var/db/aegvium", "etc", "usr/local/share/aegvium", "usr/local/share", "usr/local/libexec/aegvium", "usr/local/libexec", "usr/local", "usr", "var/db", "var", "aegvium.install"} {
		if dirs[name].Sync() != nil || dirs[name].Close() != nil {
			return errPlacement
		}
	}
	if root.Close() != nil {
		return errPlacement
	}
	// Observed placement only. Not readiness, fresh custody, cleanup of the
	// command's own process/descendants, service enablement or serving authority.
	line := fmt.Sprintf("AGCOMMISSION1 %s %x %x\n", descriptor[8:40], sha256.Sum256(descriptor), sha256.Sum256(manifest))
	if n, err := io.WriteString(os.Stdout, line); err != nil || n != len(line) {
		return errPlacement
	}
	return nil
}
