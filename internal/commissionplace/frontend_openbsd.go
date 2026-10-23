//go:build openbsd && aegvium_commission_source

// SPDX-License-Identifier: BSD-3-Clause
package commissionplace

import (
	"bytes"
	"crypto/sha256"
	"os"
	"syscall"

	"github.com/gonz0w/aegvium/internal/commission"
	"github.com/gonz0w/aegvium/internal/frontendowner"
)

// Fixed protected placement only. The installed entry still refuses. This does
// not install HAProxy, create its account, parse private keys, start a process,
// enable a service, authenticate a peer or grant serving authority.
func placeFrontend(root *os.Root, dirs map[string]*os.File, descriptor []byte) error {
	mode, err := sourceBytes(root, "aegvium.install/frontend-mode", 9, 0400)
	if err != nil {
		return errPlacement
	}
	switch string(mode) {
	case "external\n":
		// Explicitly selected external frontend; never ignore a requested bundle.
		if _, err := root.Lstat("aegvium.install/frontend"); !os.IsNotExist(err) {
			return errPlacement
		}
		return nil
	case "bundled\n":
	default:
		return errPlacement
	}
	media, err := root.OpenFile("aegvium.install/frontend", os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil || !directory(keep(media)) {
		return errPlacement
	}
	dirs["aegvium.install/frontend"] = media
	role, err := sourceBytes(root, "aegvium.install/frontend/frontend-role", 253, 0400)
	if err != nil {
		return errPlacement
	}
	listen, err := sourceBytes(root, "aegvium.install/frontend/frontend-listen", 21, 0400)
	if err != nil {
		return errPlacement
	}
	candidate, plan, err := commission.FrontendFiles(descriptor, string(role), string(listen))
	if err != nil {
		return errPlacement
	}
	entries, err := media.ReadDir(len(plan) + 4)
	if err != nil || len(entries) != len(plan)+3 {
		return errPlacement
	}
	allowed := map[string]bool{"frontend-role": true, "frontend-listen": true, "frontend-owner": true}
	for _, file := range plan {
		allowed[file.Name] = true
	}
	for _, entry := range entries {
		if !allowed[entry.Name()] || !entry.Type().IsRegular() {
			return errPlacement
		}
	}
	material := make(map[string][]byte, len(plan))
	for _, file := range plan {
		raw, e := sourceBytes(root, "aegvium.install/frontend/"+file.Name, file.Limit, 0400)
		if e != nil {
			return errPlacement
		}
		if file.Name == "server.der" || file.Name == "client.der" {
			if sha256.Sum256(raw) != file.Anchor {
				return errPlacement
			}
		}
		material[file.Name] = raw
	}
	server, _ := candidate.Anchors()
	if !commission.MatchFrontendRoot(material["inspector-root.pem"], material["server.der"], server) {
		return errPlacement
	}
	image, err := sourceBytes(root, "aegvium.install/frontend/frontend-owner", commission.MaxImageBytes, 0400)
	if err != nil {
		return errPlacement
	}
	master, group, err := accountFiles(root)
	if err != nil || !frontendAccountIdentity(master, group) {
		return errPlacement
	}
	// The packaged principal is independently distinct from the inspector. No
	// account repair/creation or adoption of an existing destination is allowed.
	if makeDirectory(root, dirs, "etc/aegvium/frontend", 0700) != nil {
		return errPlacement
	}
	for _, file := range plan {
		if installBytes(root, dirs, "etc/aegvium/frontend/"+file.Name, material[file.Name], 0600, 0) != nil {
			return errPlacement
		}
	}
	for _, file := range []struct {
		name string
		data []byte
	}{
		{"frontend-role", role}, {"frontend-listen", listen}, {"frontend.cfg", candidate.Bytes()},
	} {
		if installBytes(root, dirs, "etc/aegvium/frontend/"+file.name, file.data, 0600, 0) != nil {
			return errPlacement
		}
	}
	if installBytes(root, dirs, "etc/aegvium/frontend/pair.agpair", descriptor, 0600, 0) != nil ||
		installBytes(root, dirs, "usr/local/libexec/aegvium/frontend-owner", image, 0555, 0) != nil ||
		makeDirectory(root, dirs, "var/db/aegvium/frontend", 0700) != nil ||
		makeDirectory(root, dirs, "var/db/aegvium/frontend/consumed", 0700) != nil {
		return errPlacement
	}
	initial := frontendowner.InitialHistorySource()
	if installBytes(root, dirs, "var/db/aegvium/frontend/writer.lock", nil, 0600, 0) != nil ||
		installBytes(root, dirs, "var/db/aegvium/frontend/launch.state", initial[:], 0600, 0) != nil {
		return errPlacement
	}
	for _, name := range []string{"var/db/aegvium/frontend/consumed", "var/db/aegvium/frontend"} {
		if dirs[name].Sync() != nil || dirs[name].Close() != nil {
			return errPlacement
		}
	}
	// Recompilation binds exact descriptor/role/listen input before final readback.
	again, _, err := commission.FrontendFiles(descriptor, string(role), string(listen))
	if err != nil || again.Digest() != candidate.Digest() || !bytes.Equal(again.Bytes(), candidate.Bytes()) {
		return errPlacement
	}
	for _, name := range []string{"etc/aegvium/frontend", "aegvium.install/frontend"} {
		if dirs[name].Sync() != nil || dirs[name].Close() != nil {
			return errPlacement
		}
	}
	return nil
}
