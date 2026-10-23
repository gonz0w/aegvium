//go:build openbsd && aegvium_frontend_source

// SPDX-License-Identifier: BSD-3-Clause
package frontendowner

import (
	"bytes"
	"crypto/sha256"
	"github.com/gonz0w/aegvium/internal/localcontrol"
	"io"
	"time"

	"github.com/gonz0w/aegvium/internal/commission"
	"github.com/gonz0w/aegvium/internal/frontendconfig"
	"golang.org/x/sys/unix"
)

type successorFile struct {
	parent, file *heldFile
	name         string
	raw, next    []byte
	facts        fileFacts
}
type successorGuard struct {
	parent    *heldFile
	name      string
	limit     int
	mode, gid uint32
	facts     fileFacts
	digest    [32]byte
}
type successor struct {
	h                        *history
	checkpoint, stage, roles *heldFile
	checkpointFacts          fileFacts
	checkpointRaw            []byte
	intent                   successorFile
	targets                  [4]successorFile
	guards                   []successorGuard
	next                     [33]byte
}

// Actual owners remain process-retained on every uncertain acquisition/write/
// sync/readback/close. No reset, rollback, finalizer or replacement issuer exists.
var retainedSuccessor *successor

func prepareSuccessorQualifiedSource() error {
	if !nativeFrontendQualified {
		return ErrUnavailable
	}
	return prepareSuccessor()
}
func prepareSuccessorBeforeQualifiedSource(origin int64) error {
	if !nativeFrontendQualified {
		return ErrUnavailable
	}
	sample := time.Now()
	now, e := localcontrol.KernelMillisSource()
	if e != nil {
		return ErrUnavailable
	}
	left, e := localcontrol.Remaining(origin, now)
	if e != nil || left <= 0 {
		return ErrUnavailable
	}
	return prepareSuccessorBefore(sample.Add(left))
}
func prepareSuccessor() error { return prepareSuccessorBefore(time.Time{}) }
func prepareSuccessorBefore(deadline time.Time) error {
	h, e := openHistoryBefore(deadline)
	if e != nil {
		return ErrUnavailable
	}
	s := &successor{h: h}
	retainedSuccessor = s
	if s.prepare() != nil || s.publish() != nil {
		h.uncertain = true
		return h.fail(ErrUnavailable)
	}
	// C/U and consumed inventory are unchanged. This closes only this updater's
	// actual known descriptors; it issues neither Ready nor process retirement.
	if h.close() != nil {
		h.uncertain = true
		return ErrUnavailable
	}
	return nil
}

func (s *successor) fail() error { return s.h.fail(ErrUnavailable) }
func (s *successor) open(parent *heldFile, name string, mode, gid uint32, write bool) (*heldFile, error) {
	if gid == 0 {
		return s.h.open(parent, name, false, mode, write)
	}
	var before unix.Stat_t
	if !s.h.live() || parent.fd() < 3 || unix.Fstatat(parent.fd(), name, &before, unix.AT_SYMLINK_NOFOLLOW) != nil || !successorRoleFacts(facts(&before), gid) {
		return nil, s.fail()
	}
	flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
	if write {
		flags = flags&^unix.O_RDONLY | unix.O_RDWR
	}
	fd, e := unix.Openat(parent.fd(), name, flags, 0)
	if e != nil {
		return nil, s.fail()
	}
	f, e := s.h.hold(fd, name)
	if e != nil {
		return f, e
	}
	now, e := s.h.stat(f)
	if e != nil || !sameFile(now, facts(&before)) || !successorRoleFacts(now, gid) || !s.h.localFS(f, write) || !s.h.named(parent, f, name, now) {
		return f, s.fail()
	}
	return f, nil
}
func (s *successor) mutable(parent *heldFile, name string, mode, gid uint32, limit int) (out successorFile, e error) {
	out.parent, out.name = parent, name
	out.file, e = s.open(parent, name, mode, gid, true)
	if e != nil {
		return out, e
	}
	out.raw, e = s.h.readProtectedHeld(parent, out.file, name, limit)
	if e == nil {
		out.facts, e = s.h.stat(out.file)
	}
	return out, e
}
func (s *successor) guard(parent *heldFile, name string, mode, gid uint32, limit int, anchor [32]byte) error {
	if len(s.guards) >= 32 {
		return s.fail()
	}
	f, e := s.open(parent, name, mode, gid, false)
	if e != nil {
		return e
	}
	raw, e := s.h.readProtectedHeld(parent, f, name, limit)
	st, se := s.h.stat(f)
	digest := sha256.Sum256(raw)
	if e != nil || se != nil || len(raw) < 1 || (anchor != [32]byte{} && digest != anchor) {
		return s.fail()
	}
	if f.close() != nil {
		s.h.uncertain = true
		return s.fail()
	}
	s.guards = append(s.guards, successorGuard{parent: parent, name: name, mode: mode, gid: gid, limit: limit, facts: st, digest: digest})
	return nil
}
func (s *successor) namespace() error {
	h := s.h
	if len(h.files) < 5 || h.configEtc == nil || h.configBase == nil || h.configDir == nil {
		return s.fail()
	}
	var root unix.Stat_t
	if unix.Lstat("/", &root) != nil {
		return s.fail()
	}
	opened, e := h.stat(h.files[0])
	if e != nil || !sameFile(facts(&root), opened) || !protected(opened, true, 0755) {
		return s.fail()
	}
	for i, name := range []string{"var", "db", "aegvium", "frontend"} {
		mode := uint32(0755)
		if i >= 2 {
			mode = 0700
		}
		f, e := h.stat(h.files[i+1])
		if e != nil || !protected(f, true, mode) || !h.named(h.files[i], h.files[i+1], name, f) {
			return s.fail()
		}
	}
	for _, p := range []struct {
		parent, file *heldFile
		name         string
		mode         uint32
	}{
		{h.files[0], h.configEtc, "etc", 0755}, {h.configEtc, h.configBase, "aegvium", 0755}, {h.configBase, h.configDir, "frontend", 0700},
	} {
		f, e := h.stat(p.file)
		if e != nil || !protected(f, true, p.mode) || !h.named(p.parent, p.file, p.name, f) {
			return s.fail()
		}
	}
	if s.roles != nil {
		f, e := h.stat(s.roles)
		if e != nil || !protected(f, true, 0755) || !h.named(h.configBase, s.roles, "inspector", f) {
			return s.fail()
		}
	}
	if s.stage != nil {
		f, e := h.stat(s.stage)
		if e != nil || !protected(f, true, 0700) || !h.named(h.files[0], s.stage, "aegvium.next", f) {
			return s.fail()
		}
	}
	return nil
}
func (s *successor) verify() error {
	h := s.h
	if s.namespace() != nil {
		return s.fail()
	}
	st, e := h.stat(s.checkpoint)
	raw, e2 := h.readProtectedHeld(h.inspectorDir, s.checkpoint, "launch.state", 128)
	frame, e3 := h.readLifetime()
	lf, e4 := h.lifetimeFacts()
	if e != nil || e2 != nil || e3 != nil || e4 != nil || !sameFile(st, s.checkpointFacts) || !bytes.Equal(raw, s.checkpointRaw) || frame != h.stateFrame || !sameFile(lf, h.stateFacts) {
		return s.fail()
	}
	for _, g := range s.guards {
		f, e := s.open(g.parent, g.name, g.mode, g.gid, false)
		if e != nil {
			return e
		}
		raw, e := h.readProtectedHeld(g.parent, f, g.name, g.limit)
		st, se := h.stat(f)
		if e != nil || se != nil || !sameFile(st, g.facts) || sha256.Sum256(raw) != g.digest {
			return s.fail()
		}
		if f.close() != nil {
			h.uncertain = true
			return s.fail()
		}
	}
	return nil
}
func (s *successor) prepare() error {
	h := s.h
	phase, priorRecord, valid := parseLifetime(h.stateFrame)
	if !valid || phase != 'C' || priorRecord != h.stateRecord || h.initialState || h.uncertain || h.child != nil || h.launchCommitted {
		return s.fail()
	}
	old, e := h.loadRecord()
	if e != nil || old != h.stateRecord || !dataProfileRecord(old[:]) || h.checkFrontendPrincipal() != nil {
		return s.fail()
	}
	h.record = old
	mode, e := h.readBase("frontend-mode", 9)
	if e != nil || string(mode) != "bundled\n" || s.guard(h.configBase, "frontend-mode", 0600, 0, 9, sha256.Sum256(mode)) != nil {
		return s.fail()
	}
	s.checkpoint, e = h.open(h.inspectorDir, "launch.state", false, 0600, true)
	if e != nil || h.lockExclusive(s.checkpoint) != nil {
		return s.fail()
	}
	locked, e := h.stat(s.checkpoint)
	if e != nil || !protected(locked, false, 0600) || locked.size != 128 || !h.named(h.inspectorDir, s.checkpoint, "launch.state", locked) {
		return s.fail()
	}
	s.checkpointRaw, e = h.readProtectedHeld(h.inspectorDir, s.checkpoint, "launch.state", 128)
	if e != nil || !inspectorClean(s.checkpointRaw, string(old[8:40])) {
		return s.fail()
	}
	if h.waitLocks {
		// Both exclusive histories are now trusted clean before the common cutoff.
		// Only NEW configuration preparation gets its separate existing bound.
		if !h.live() {
			return s.fail()
		}
		now := time.Now()
		h.started, h.end = now, now.Add(4*time.Second)
		h.waitLocks = false
	}
	s.checkpointFacts, e = h.stat(s.checkpoint)
	if e != nil {
		return e
	}
	s.intent, e = s.mutable(h.inspectorDir, "launch.intent", 0600, 0, 33)
	if e != nil || !launchIntent(s.intent.raw, string(old[8:40])) {
		return s.fail()
	}
	s.targets[0], e = s.mutable(h.inspectorDir, "pair.snapshot", 0600, 0, 8192)
	if e != nil || !bytes.Equal(s.targets[0].raw, h.descriptor) {
		return s.fail()
	}
	s.targets[1], e = s.mutable(h.configDir, "pair.agpair", 0600, 0, 8192)
	if e != nil || !bytes.Equal(s.targets[1].raw, h.descriptor) {
		return s.fail()
	}
	roles, e := h.open(h.configBase, "inspector", true, 0755, false)
	if e != nil {
		return e
	}
	s.roles = roles
	var bs unix.Stat_t
	if unix.Fstatat(roles.fd(), "backend.conf", &bs, unix.AT_SYMLINK_NOFOLLOW) != nil || !successorRoleFacts(facts(&bs), bs.Gid) {
		return s.fail()
	}
	s.targets[2], e = s.mutable(roles, "backend.conf", 0440, bs.Gid, 8192)
	if e != nil {
		return e
	}
	s.targets[3], e = s.mutable(h.configDir, "frontend.cfg", 0600, 0, 32768)
	if e != nil {
		return e
	}
	stage, e := h.open(h.files[0], "aegvium.next", true, 0700, false)
	if e != nil {
		return e
	}
	s.stage = stage
	names, e := stage.file.Readdirnames(3)
	if e != io.EOF && e != nil || len(names) != 2 || !(names[0] == "pair.snapshot" && names[1] == "backend.conf" || names[1] == "pair.snapshot" && names[0] == "backend.conf") {
		return s.fail()
	}
	readStage := func(name string, limit int) ([]byte, error) {
		f, e := h.open(stage, name, false, 0400, false)
		if e != nil {
			return nil, e
		}
		raw, e := h.readProtectedHeld(stage, f, name, limit)
		if f.close() != nil {
			h.uncertain = true
			return nil, s.fail()
		}
		return raw, e
	}
	next, e := readStage("pair.snapshot", 8192)
	backend, e2 := readStage("backend.conf", 8192)
	if e != nil || e2 != nil || !successorData(h.descriptor, next, s.targets[2].raw, backend, old) {
		return s.fail()
	}
	listen, e := h.readLocal("frontend-listen", 21)
	if e != nil {
		return e
	}
	prior, frontPlan, e := commission.FrontendFiles(h.descriptor, h.role, string(listen))
	after, e2 := frontendconfig.Compile(next, h.role, string(listen))
	if e != nil || e2 != nil || !bytes.Equal(prior.Bytes(), s.targets[3].raw) || len(after.Bytes()) != len(s.targets[3].raw) {
		return s.fail()
	}
	// Every generation-bound input is checked. Role keys/anchors stay byte- and
	// inode-identical; their real loader/TLS validity remains native acceptance.
	plan, e := commission.RoleFiles(h.descriptor)
	backPlan, e2 := commission.BackendFiles(h.descriptor, s.targets[2].raw)
	if e != nil || e2 != nil {
		return s.fail()
	}
	plan = append(plan, backPlan...)
	entries, e := roles.file.Readdirnames(24)
	if e != io.EOF && e != nil || len(entries) != len(plan) {
		return s.fail()
	}
	allowed := make(map[string]bool, len(plan))
	for _, p := range plan {
		allowed[p.Name] = true
	}
	for _, name := range entries {
		if !allowed[name] {
			return s.fail()
		}
	}
	for _, p := range plan {
		if p.Name != "backend.conf" && s.guard(roles, p.Name, 0440, bs.Gid, int(p.Limit), p.Anchor) != nil {
			return s.fail()
		}
	}
	for _, p := range frontPlan {
		if s.guard(h.configDir, p.Name, 0600, 0, int(p.Limit), p.Anchor) != nil {
			return s.fail()
		}
	}
	for _, p := range []struct {
		name  string
		limit int
	}{{"frontend-role", 253}, {"frontend-listen", 21}} {
		raw := []byte(h.role)
		if p.name == "frontend-listen" {
			raw = listen
		}
		if s.guard(h.configDir, p.name, 0600, 0, p.limit, sha256.Sum256(raw)) != nil {
			return s.fail()
		}
	}
	if s.guard(stage, "pair.snapshot", 0400, 0, 8192, sha256.Sum256(next)) != nil || s.guard(stage, "backend.conf", 0400, 0, 8192, sha256.Sum256(backend)) != nil {
		return s.fail()
	}
	copy(s.next[:32], next[8:40])
	s.next[32] = '\n'
	// Detached fixed replacements only, no supplied path, new file or identity.
	s.targets[0].next = bytes.Clone(next)
	s.targets[1].next = bytes.Clone(next)
	s.targets[2].next = bytes.Clone(backend)
	s.targets[3].next = after.Bytes()
	return s.verify()
}

// One exact same-size write, sync, readback, current identity, parent sync and
// second readback. No short continuation, truncate, rename, repair or retry.
func (s *successor) replace(f *successorFile, old, next []byte) error {
	h := s.h
	if len(old) != len(next) || len(old) == 0 || !h.live() || s.namespace() != nil {
		return s.fail()
	}
	before, e := h.stat(f.file)
	raw, e2 := h.readProtectedHeld(f.parent, f.file, f.name, len(old))
	if e != nil || e2 != nil || !sameFile(before, f.facts) || !bytes.Equal(raw, old) {
		return s.fail()
	}
	n, e := unix.Pwrite(f.file.fd(), next, 0)
	if e != nil || n != len(next) || unix.Fsync(f.file.fd()) != nil {
		return s.fail()
	}
	raw, e = h.readProtectedHeld(f.parent, f.file, f.name, len(next))
	after, e2 := h.stat(f.file)
	if e != nil || e2 != nil || !bytes.Equal(raw, next) || !successorSamePlacement(before, after) || unix.Fsync(f.parent.fd()) != nil {
		return s.fail()
	}
	raw, e = h.readProtectedHeld(f.parent, f.file, f.name, len(next))
	again, e2 := h.stat(f.file)
	if e != nil || e2 != nil || !bytes.Equal(raw, next) || !sameFile(after, again) || !h.live() || s.namespace() != nil {
		return s.fail()
	}
	f.facts = again
	return nil
}
func (s *successor) verifyTargets() error {
	for _, t := range s.targets {
		mode := t.facts.mode & 07777
		f, e := s.open(t.parent, t.name, mode, t.facts.gid, false)
		if e != nil {
			return e
		}
		raw, e := s.h.readProtectedHeld(t.parent, f, t.name, len(t.next))
		st, se := s.h.stat(f)
		if e != nil || se != nil || !sameFile(st, t.facts) || !bytes.Equal(raw, t.next) {
			return s.fail()
		}
		if f.close() != nil {
			s.h.uncertain = true
			return s.fail()
		}
	}
	return nil
}
func (s *successor) publish() error {
	if s.verify() != nil {
		return s.fail()
	}
	// A zero intent is invalid to BOTH launch participants. No replacement starts
	// before its complete file+directory durability/readback/identity boundary.
	invalid := append(bytes.Repeat([]byte{'0'}, 32), '\n')
	if s.replace(&s.intent, s.intent.raw, invalid) != nil {
		return s.fail()
	}
	for i := range s.targets {
		f := &s.targets[i]
		if s.verify() != nil || s.replace(f, f.raw, f.next) != nil {
			return s.fail()
		}
		if f.file.close() != nil {
			s.h.uncertain = true
			return s.fail()
		}
	}
	if s.verify() != nil || s.verifyTargets() != nil {
		return s.fail()
	}
	// All replacement files are durable and their owned writes closed. A final
	// failed/uncertain preparation commit retains every remaining owner, with no rollback
	// or retry. A future qualified consumer still needs the full provenance chain.
	return s.replace(&s.intent, invalid, s.next[:])
}
func (h *history) readBase(name string, limit int) ([]byte, error) {
	f, e := h.open(h.configBase, name, false, 0600, false)
	if e != nil {
		return nil, e
	}
	raw, e := h.readProtectedHeld(h.configBase, f, name, limit)
	if f.close() != nil {
		h.uncertain = true
		return nil, h.fail(ErrUnavailable)
	}
	return raw, e
}
