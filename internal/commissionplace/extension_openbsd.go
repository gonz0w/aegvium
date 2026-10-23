//go:build openbsd && aegvium_commission_source

// SPDX-License-Identifier: BSD-3-Clause
package commissionplace

import (
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/gonz0w/aegvium/internal/commission"
)

var supervisorInputs = []string{
	"main.c", "controller.c", "controller.h", "control_frame.c", "control_frame.h",
	"launch_storage.c", "launch_storage.h", "storage_openbsd.c", "storage_os.h",
	"native_construction.c", "native_construction.h", "native_openbsd.c", "native_os.h",
	"launch_source.inc", "launch_source_openbsd.c", "launch_source_os.h",
	"diagnostics_source.inc",
}

// Reads owned private media only. No credential is parsed or emitted. Every
// opened handle receives one Close attempt; partial image state is retained.
func sourceBytes(root *os.Root, name string, limit int64, mode os.FileMode) ([]byte, error) {
	f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, errPlacement
	}
	keep(f)
	initial, err := f.Stat()
	if err != nil || initial.Size() < 1 || initial.Size() > limit || !metadata(f, mode, initial.Size()) {
		return nil, errPlacement
	}
	current := func() bool {
		named, e := root.Lstat(name)
		fd, e2 := f.Stat()
		return e == nil && e2 == nil && os.SameFile(initial, named) && os.SameFile(initial, fd) && metadata(f, mode, initial.Size())
	}
	if !current() {
		return nil, errPlacement
	}
	a, b := make([]byte, initial.Size()+1), make([]byte, initial.Size()+1)
	n, e := f.ReadAt(a, 0)
	m, e2 := f.ReadAt(b, 0)
	if e != io.EOF || e2 != io.EOF || int64(n) != initial.Size() || n != m || !bytes.Equal(a[:n], b[:m]) || !current() || f.Close() != nil {
		return nil, errPlacement
	}
	return a[:n], nil
}

func fixedCommand(program string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, program, args...)
	command.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}
	command.Dir = "/aegvium.install"
	// No shell, supplied argv, inherited descriptors, credential/log output or
	// product execution. Direct-child wait is not descendant-reclamation proof.
	if command.Run() != nil || ctx.Err() != nil {
		return errPlacement
	}
	return nil
}

func makeDirectory(root *os.Root, dirs map[string]*os.File, name string, mode os.FileMode) error {
	if root.Mkdir(name, 0700) != nil {
		return errPlacement
	} // Existing paths refuse.
	f, e := root.OpenFile(name, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if e != nil || !directory(keep(f)) || f.Chown(0, 0) != nil || f.Chmod(mode) != nil || f.Sync() != nil {
		return errPlacement
	}
	named, e := root.Lstat(name)
	opened, e2 := f.Stat()
	if e != nil || e2 != nil || !os.SameFile(named, opened) {
		return errPlacement
	}
	dirs[name] = f
	parent := name[:strings.LastIndexByte(name, '/')]
	if dirs[parent] == nil || dirs[parent].Sync() != nil {
		return errPlacement
	}
	return nil
}

func installBytes(root *os.Root, dirs map[string]*os.File, name string, data []byte, mode os.FileMode, gid int) error {
	f, e := root.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return errPlacement
	}
	keep(f)
	if n, e := f.Write(data); e != nil || n != len(data) {
		return errPlacement
	}
	if f.Chown(0, gid) != nil || f.Chmod(mode) != nil || f.Sync() != nil {
		return errPlacement
	}
	info, e := f.Stat()
	named, e2 := root.Lstat(name)
	st, ok := infoSys(info)
	if e != nil || e2 != nil || !ok || !os.SameFile(info, named) || !info.Mode().IsRegular() ||
		st.Uid != 0 || st.Gid != uint32(gid) || st.Nlink != 1 || st.Mode&07777 != uint32(mode) || info.Size() != int64(len(data)) {
		return errPlacement
	}
	back := make([]byte, len(data)+1)
	n, e := f.ReadAt(back, 0)
	current, e2 := f.Stat()
	path, e3 := root.Lstat(name)
	if e != io.EOF || n != len(data) || !bytes.Equal(back[:n], data) || e2 != nil || e3 != nil ||
		!os.SameFile(info, current) || !os.SameFile(info, path) ||
		!placedFile(current, mode, int64(len(data)), gid) || !placedFile(path, mode, int64(len(data)), gid) || f.Close() != nil {
		return errPlacement
	}
	parent := name[:strings.LastIndexByte(name, '/')]
	if dirs[parent] == nil || dirs[parent].Sync() != nil {
		return errPlacement
	}
	return nil
}

func accountFiles(root *os.Root) (string, string, error) {
	// Bounded readback of this fresh target's databases only; never host input.
	master, e := sourceBytes(root, "etc/master.passwd", 262144, 0600)
	if e != nil {
		return "", "", e
	}
	group, e := sourceBytes(root, "etc/group", 262144, 0644)
	if e != nil {
		return "", "", e
	}
	return string(master), string(group), nil
}

func dedicatedAccount(root *os.Root) (int, error) {
	master, group, e := accountFiles(root)
	if e != nil {
		return 0, e
	}
	for _, text := range []string{master, group} {
		for _, line := range strings.Split(text, "\n") {
			if strings.HasPrefix(line, "_aegvium:") {
				return 0, errPlacement
			}
		}
	}
	if fixedCommand("/usr/sbin/useradd", "-g", "=uid", "-d", "/var/empty", "-s", "/sbin/nologin", "-p", "*", "-c", "Aegvium inspector", "_aegvium") != nil {
		return 0, errPlacement
	}
	master, group, e = accountFiles(root)
	if e != nil {
		return 0, e
	}
	gid, e := accountIdentity(master, group)
	if e != nil {
		return 0, e
	}
	// Persist every actual account database after the fixed tool returns. This
	// source ordering still needs native atomicity, lookup and descendant proof.
	for _, file := range []struct {
		name string
		mode os.FileMode
	}{
		{"etc/master.passwd", 0600}, {"etc/passwd", 0644}, {"etc/group", 0644},
		{"etc/pwd.db", 0644}, {"etc/spwd.db", 0600},
	} {
		f, e := root.OpenFile(file.name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if e != nil {
			return 0, errPlacement
		}
		keep(f)
		info, e := f.Stat()
		named, e2 := root.Lstat(file.name)
		if e != nil || e2 != nil || info.Size() < 1 || info.Size() > 4194304 || !os.SameFile(info, named) ||
			!metadata(f, file.mode, info.Size()) || f.Sync() != nil || f.Close() != nil {
			return 0, errPlacement
		}
	}
	return gid, nil
}

func readRoleMaterials(root *os.Root, dirs map[string]*os.File, descriptor []byte) ([]commission.RoleFile, [][]byte, error) {
	plan, e := commission.RoleFiles(descriptor)
	if e != nil {
		return nil, nil, errPlacement
	}
	for _, name := range []string{"etc", "aegvium.install/roles"} {
		if dirs[name] != nil {
			continue
		}
		f, e := root.OpenFile(name, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
		if e != nil || !directory(keep(f)) {
			return nil, nil, errPlacement
		}
		dirs[name] = f
	}
	privateData, e := sourceBytes(root, "aegvium.install/roles/backend.conf", 8192, 0400)
	if e != nil {
		return nil, nil, errPlacement
	}
	privatePlan, e := commission.BackendFiles(descriptor, privateData)
	if e != nil {
		return nil, nil, errPlacement
	}
	plan = append(plan, privatePlan...)
	entries, e := dirs["aegvium.install/roles"].ReadDir(24)
	if e != nil || len(entries) != len(plan) {
		return nil, nil, errPlacement
	}
	allowed := make(map[string]bool)
	for _, file := range plan {
		allowed[file.Name] = true
	}
	for _, entry := range entries {
		if !allowed[entry.Name()] || !entry.Type().IsRegular() {
			return nil, nil, errPlacement
		}
	}
	materials := make([][]byte, len(plan))
	for i, file := range plan {
		materials[i], e = sourceBytes(root, "aegvium.install/roles/"+file.Name, file.Limit, 0400)
		if e != nil || strings.HasSuffix(file.Name, ".der") && sha256.Sum256(materials[i]) != file.Anchor {
			return nil, nil, errPlacement
		}
		if file.Name == "backend.conf" && !bytes.Equal(materials[i], privateData) {
			return nil, nil, errPlacement
		}
	}
	return plan, materials, nil
}

func placeExtension(root *os.Root, dirs map[string]*os.File, descriptor []byte) ([32]byte, error) {
	var zero [32]byte
	plan, materials, e := readRoleMaterials(root, dirs, descriptor)
	if e != nil {
		return zero, errPlacement
	}
	f, e := root.OpenFile("aegvium.install/supervisor-source", os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if e != nil || !directory(keep(f)) {
		return zero, errPlacement
	}
	dirs["aegvium.install/supervisor-source"] = f
	inputs := make(map[string][32]byte)
	entries, e := dirs["aegvium.install/supervisor-source"].ReadDir(len(supervisorInputs) + 1)
	if e != nil || len(entries) != len(supervisorInputs) {
		return zero, errPlacement
	}
	total := 0
	for _, name := range supervisorInputs {
		data, e := sourceBytes(root, "aegvium.install/supervisor-source/"+name, 65536, 0400)
		total += len(data)
		if e != nil || total > 262144 {
			return zero, errPlacement
		}
		inputs[name] = sha256.Sum256(data)
	}
	if makeDirectory(root, dirs, "aegvium.install/build", 0700) != nil {
		return zero, errPlacement
	}
	args := []string{"-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic", "-DAEG_INSPECTOR_SOURCE", "-I/aegvium.install/supervisor-source"}
	for _, name := range []string{"main.c", "controller.c", "control_frame.c", "launch_storage.c", "storage_openbsd.c", "native_construction.c", "native_openbsd.c", "launch_source_openbsd.c"} {
		args = append(args, "/aegvium.install/supervisor-source/"+name)
	}
	args = append(args, "-o", "/aegvium.install/build/supervisor")
	if fixedCommand("/usr/bin/cc", args...) != nil {
		return zero, errPlacement
	}
	for name, pin := range inputs {
		data, e := sourceBytes(root, "aegvium.install/supervisor-source/"+name, 65536, 0400)
		if e != nil || sha256.Sum256(data) != pin {
			return zero, errPlacement
		}
	}
	// The compiler owns one fresh private output; make it read-only before readback.
	f, e = root.OpenFile("aegvium.install/build/supervisor", os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return zero, errPlacement
	}
	keep(f)
	if f.Chmod(0400) != nil || f.Sync() != nil || f.Close() != nil {
		return zero, errPlacement
	}
	image, e := sourceBytes(root, "aegvium.install/build/supervisor", 1048576, 0400)
	if e != nil {
		return zero, errPlacement
	}
	if installBytes(root, dirs, "usr/local/libexec/aegvium/supervisor", image, 0555, 0) != nil {
		return zero, errPlacement
	}
	gid, e := dedicatedAccount(root)
	if e != nil {
		return zero, e
	}
	if makeDirectory(root, dirs, "etc/aegvium", 0755) != nil || makeDirectory(root, dirs, "etc/aegvium/inspector", 0755) != nil {
		return zero, errPlacement
	}
	for i, file := range plan {
		if installBytes(root, dirs, "etc/aegvium/inspector/"+file.Name, materials[i], 0440, gid) != nil {
			return zero, errPlacement
		}
	}
	if placeFrontend(root, dirs, descriptor) != nil {
		return zero, errPlacement
	}
	for _, name := range []string{"etc/aegvium/inspector", "etc/aegvium", "etc", "aegvium.install/build", "aegvium.install/roles", "aegvium.install/supervisor-source"} {
		if dirs[name].Sync() != nil || dirs[name].Close() != nil {
			return zero, errPlacement
		}
	}
	return sha256.Sum256(image), nil
}
