//go:build openbsd && aegvium_frontend_source

// Adapted from private Vectivium e28959892903225887d855677c307712a59ce071; see LICENSE.Vectivium.
// No public relicensing is made.
package frontendowner

import (
	"bytes"
	"io"
	"os"
	"sync"
	"time"

	"github.com/gonz0w/aegvium/internal/frontendclient"
	"github.com/gonz0w/aegvium/internal/localcontrol"
	"golang.org/x/sys/unix"
)

type heldFile struct {
	file     *os.File
	closed   bool
	closeErr error
}

func (f *heldFile) fd() int {
	if f == nil || f.closed || f.file == nil {
		return -1
	}
	return int(f.file.Fd())
}

func (f *heldFile) close() error {
	if f == nil || f.closed {
		return ErrUnavailable
	}
	f.closed = true // consume before the fallible close; never retry this number
	f.closeErr = f.file.Close()
	return f.closeErr
}

type history struct {
	started, end                   time.Time
	files                          []*heldFile
	consumedDir, lock, token       *heldFile
	record                         [104]byte
	attempted, created, consumed   bool
	uncertain                      bool
	cause                          error
	child                          *originalChild
	service                        *localcontrol.Frontend
	cancelService                  func()
	configDir                      *heldFile
	descriptor                     []byte
	role                           string
	frontend                       *preparedFrontend
	historyDir, lifetime           *heldFile
	stateFrame                     [160]byte
	stateFacts                     fileFacts
	stateRecord                    [104]byte
	initialState, launchCommitted  bool
	beginAttempted, cleanAttempted bool
}

// Retention is intentional even on error: no finalizer, later constructor or
// replacement may erase unknown close/birth/wait ownership.
var historyConstruction struct {
	sync.Mutex
	attempted bool
	owner     *history
}

func facts(st *unix.Stat_t) fileFacts {
	return fileFacts{device: uint64(st.Dev), inode: st.Ino, mode: uint32(st.Mode), uid: st.Uid, gid: st.Gid, links: uint64(st.Nlink), size: st.Size, modifiedSec: st.Mtim.Sec, modifiedNsec: st.Mtim.Nsec, changedSec: st.Ctim.Sec, changedNsec: st.Ctim.Nsec}
}

func (h *history) fail(err error) error {
	if h.cause == nil {
		h.cause = err
	}
	return ErrUnavailable
}

func (h *history) live() bool {
	return h.cause == nil && before(time.Now(), h.started, h.end)
}

func (h *history) hold(fd int, name string) (*heldFile, error) {
	if fd < 0 {
		return nil, h.fail(ErrUnavailable)
	}
	f := &heldFile{file: os.NewFile(uintptr(fd), name)}
	h.files = append(h.files, f)
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	if f.file == nil || fd < 3 || err != nil || flags&unix.FD_CLOEXEC == 0 {
		return f, h.fail(ErrUnavailable)
	}
	return f, nil
}

func (h *history) stat(f *heldFile) (fileFacts, error) {
	if f.fd() < 0 || !h.live() {
		return fileFacts{}, h.fail(ErrUnavailable)
	}
	var st unix.Stat_t
	if err := unix.Fstat(f.fd(), &st); err != nil {
		return fileFacts{}, h.fail(err)
	}
	return facts(&st), nil
}

func (h *history) localFS(f *heldFile, writing bool) bool {
	var fs unix.Statfs_t
	if !h.live() || unix.Fstatfs(f.fd(), &fs) != nil || string(bytes.TrimRight(fs.F_fstypename[:], "\x00")) != "ffs" || writing && fs.F_flags&unix.MNT_RDONLY != 0 {
		h.fail(ErrUnavailable)
		return false
	}
	return true
}

func (h *history) named(parent, f *heldFile, name string, want fileFacts) bool {
	var st unix.Stat_t
	if !h.live() || unix.Fstatat(parent.fd(), name, &st, unix.AT_SYMLINK_NOFOLLOW) != nil || !sameFile(facts(&st), want) {
		h.fail(ErrUnavailable)
		return false
	}
	got, err := h.stat(f)
	return err == nil && sameFile(got, want) && h.live()
}

func (h *history) open(parent *heldFile, name string, directory bool, perm uint32, write bool) (*heldFile, error) {
	if !h.live() || parent.fd() < 0 {
		return nil, h.fail(ErrUnavailable)
	}
	var entry unix.Stat_t
	if unix.Fstatat(parent.fd(), name, &entry, unix.AT_SYMLINK_NOFOLLOW) != nil || !protected(facts(&entry), directory, perm) || !h.live() {
		return nil, h.fail(ErrUnavailable)
	}
	flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK
	if directory {
		flags |= unix.O_DIRECTORY
	} else if write {
		flags = flags&^unix.O_RDONLY | unix.O_RDWR
	}
	fd, err := unix.Openat(parent.fd(), name, flags, 0)
	if err != nil {
		return nil, h.fail(err)
	}
	f, err := h.hold(fd, name)
	if err != nil {
		return f, err
	}
	st, err := h.stat(f)
	if err != nil || !sameFile(st, facts(&entry)) || !protected(st, directory, perm) || !h.localFS(f, write) || !h.named(parent, f, name, st) {
		return f, h.fail(ErrUnavailable)
	}
	return f, nil
}

func openHistory() (h *history, err error) {
	historyConstruction.Lock()
	defer historyConstruction.Unlock()
	if historyConstruction.attempted {
		return nil, ErrUnavailable
	}
	historyConstruction.attempted = true
	now := time.Now()
	h = &history{started: now, end: now.Add(4 * time.Second)}
	historyConstruction.owner = h
	complete := false
	defer func() {
		if !complete {
			h.fail(ErrUnavailable)
			h.close()
			err = ErrUnavailable
		}
	}()
	if os.Getuid() != 0 || os.Geteuid() != 0 || os.Getgid() != 0 || os.Getegid() != 0 {
		return h, ErrUnavailable
	}
	for fd := 0; fd < 3; fd++ {
		if _, e := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); e != nil {
			return h, ErrUnavailable
		}
	}
	fd, e := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return h, e
	}
	root, e := h.hold(fd, "/")
	if e != nil {
		return h, e
	}
	st, e := h.stat(root)
	if e != nil || !protected(st, true, 0755) || !h.localFS(root, false) {
		return h, ErrUnavailable
	}
	parent := root
	for _, component := range []struct {
		name string
		perm uint32
	}{{"var", 0755}, {"db", 0755}, {"aegvium", 0700}, {"frontend", 0700}} {
		parent, e = h.open(parent, component.name, true, component.perm, true)
		if e != nil {
			return h, e
		}
	}
	h.historyDir = parent
	h.lock, e = h.open(parent, "writer.lock", false, 0600, true)
	if e != nil {
		return h, e
	}
	st, e = h.stat(h.lock)
	if e != nil || st.size != 0 || unix.Flock(h.lock.fd(), unix.LOCK_EX|unix.LOCK_NB) != nil || !h.named(parent, h.lock, "writer.lock", st) {
		return h, ErrUnavailable
	}
	h.consumedDir, e = h.open(parent, "consumed", true, 0700, true)
	if e != nil || h.openLifetime() != nil || !h.inventory() {
		return h, ErrUnavailable
	}
	complete = true
	return h, nil
}

func (h *history) readRecord(f *heldFile) ([]byte, error) {
	st, err := h.stat(f)
	if err != nil || !protected(st, false, 0600) || st.size != 104 {
		return nil, h.fail(ErrUnavailable)
	}
	raw := make([]byte, 104)
	if n, e := f.file.ReadAt(raw, 0); n != 104 || e != nil {
		return nil, h.fail(ErrUnavailable)
	}
	var tail [1]byte
	if n, e := f.file.ReadAt(tail[:], 104); n != 0 || e != io.EOF {
		return nil, h.fail(ErrUnavailable)
	}
	after, err := h.stat(f)
	if err != nil || !sameFile(st, after) || !h.live() {
		return nil, h.fail(ErrUnavailable)
	}
	return raw, nil
}

func (h *history) inventory() bool {
	if !h.live() {
		return false
	}
	names, err := h.consumedDir.file.Readdirnames(historyLimit + 1)
	if err != nil && err != io.EOF || !inventoryCapacity(len(names)) {
		h.fail(ErrUnavailable)
		return false // full history, including an attempted4097th name, refuses
	}
	matched := h.initialState
	seen := make(map[string]bool, len(names))
	for _, name := range names {
		if !generation(name) || seen[name] {
			h.fail(ErrUnavailable)
			return false
		}
		seen[name] = true
		f, e := h.open(h.consumedDir, name, false, 0600, false)
		if e != nil {
			return false
		}
		raw, e := h.readRecord(f)
		st, se := h.stat(f)
		valid := e == nil && se == nil && inventoryEntry(name, st, raw) && h.named(h.consumedDir, f, name, st)
		if valid && !h.initialState && name == string(h.stateRecord[8:40]) {
			matched = bytes.Equal(raw, h.stateRecord[:])
			if !matched {
				valid = false
			}
		}
		if ce := f.close(); ce != nil {
			h.uncertain = true
			valid = false
		}
		if !valid {
			h.fail(ErrUnavailable)
			return false
		}
	}
	if !matched {
		h.fail(ErrUnavailable)
		return false
	}
	return h.live()
}

// loadRecord uses only actual fixed protected local files and the existing
// descriptor parser. It reads no private credential or backend configuration.
func (h *history) loadRecord() ([104]byte, error) {
	root := h.files[0]
	etc, err := h.open(root, "etc", true, 0755, false)
	if err != nil {
		return [104]byte{}, err
	}
	base, err := h.open(etc, "aegvium", true, 0755, false)
	if err != nil {
		return [104]byte{}, err
	}
	config, err := h.open(base, "frontend", true, 0700, false)
	if err != nil {
		return [104]byte{}, err
	}
	h.configDir = config
	descriptor, err := h.readLocal("pair.agpair", 8192)
	if err != nil {
		return [104]byte{}, h.fail(err)
	}
	role, err := h.readLocal("frontend-role", 253)
	if err != nil {
		return [104]byte{}, h.fail(err)
	}
	record, err := frontendclient.ConfigurationTupleSource(descriptor, string(role))
	if err != nil || !h.live() {
		return [104]byte{}, h.fail(ErrUnavailable)
	}
	h.descriptor, h.role = descriptor, string(role)
	return record, nil
}

// readLocal has no caller path component: callers use fixed literal basenames.
// Retain every actual owner and consume Close once even on uncertainty.
func (h *history) readLocal(name string, cap int) ([]byte, error) {
	f, e := h.open(h.configDir, name, false, 0600, false)
	if e != nil {
		return nil, e
	}
	raw, e := h.readLocalHeld(f, name, cap)
	if ce := f.close(); ce != nil {
		h.uncertain, e = true, ErrUnavailable
	}
	if e != nil {
		return nil, h.fail(e)
	}
	return raw, nil
}

func (h *history) readLocalHeld(f *heldFile, name string, cap int) ([]byte, error) {
	return h.readProtectedHeld(h.configDir, f, name, cap)
}

func (h *history) readProtectedHeld(parent, f *heldFile, name string, cap int) ([]byte, error) {
	st, e := h.stat(f)
	if e != nil || st.size <= 0 || st.size > int64(cap) {
		return nil, h.fail(ErrUnavailable)
	}
	raw := make([]byte, int(st.size))
	if n, re := f.file.ReadAt(raw, 0); n != len(raw) || re != nil || !h.named(parent, f, name, st) {
		return nil, h.fail(ErrUnavailable)
	}
	return raw, nil
}

func (h *history) consumeLocal() error {
	if h.attempted || !h.live() || h.uncertain {
		return h.fail(ErrUnavailable)
	}
	h.attempted = true
	record, err := h.loadRecord()
	if err != nil {
		return err
	}
	h.record = record
	name := string(record[8:40])
	if !recordData(record[:], name) || !h.live() {
		return h.fail(ErrUnavailable)
	}
	fd, err := unix.Openat(h.consumedDir.fd(), name, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0600)
	if err != nil {
		return h.fail(err)
	}
	h.created = true // exclusive name is burned before any later operation
	h.token, err = h.hold(fd, name)
	if err != nil {
		return err
	}
	good := false
	defer func() {
		if !h.token.closed {
			if ce := h.token.close(); ce != nil {
				h.uncertain = true
			}
		}
		if !good {
			h.fail(ErrUnavailable)
		}
	}()
	st, err := h.stat(h.token)
	if err != nil || !protected(st, false, 0600) || st.size != 0 || !h.named(h.consumedDir, h.token, name, st) {
		return h.fail(ErrUnavailable)
	}
	if n, e := h.token.file.Write(record[:]); n != len(record) || e != nil || !h.live() {
		return h.fail(ErrUnavailable)
	}
	raw, err := h.readRecord(h.token)
	after, se := h.stat(h.token)
	if err != nil || se != nil || after.device != st.device || after.inode != st.inode || !bytes.Equal(raw, record[:]) || !h.named(h.consumedDir, h.token, name, after) {
		return h.fail(ErrUnavailable)
	}
	if !h.live() || unix.Fsync(h.token.fd()) != nil || !h.live() || unix.Fsync(h.consumedDir.fd()) != nil || !h.live() {
		return h.fail(ErrUnavailable)
	}
	if err := h.token.close(); err != nil {
		h.uncertain = true
		return h.fail(err)
	}
	if !h.live() {
		return h.fail(ErrUnavailable)
	}
	h.consumed, good = true, true
	return nil
}

func (h *history) close() error {
	if h.uncertain {
		return h.fail(ErrUnavailable)
	}
	if h.child != nil && (h.child.phase != childConsumed && h.child.phase != childUnused || h.child.uncertain) {
		h.uncertain = true
		return h.fail(ErrUnavailable)
	}
	// Non-storage handles close only after the original child is terminal. Keep
	// the actual state/namespace/writer handles until the final durable settlement.
	for i := len(h.files) - 1; i >= 0; i-- {
		f := h.files[i]
		if f == h.lifetime || f == h.historyDir || f == h.lock {
			continue
		}
		if !f.closed && f.close() != nil {
			h.uncertain = true
			return h.fail(ErrUnavailable)
		}
	}
	if h.launchCommitted {
		if h.child != nil && (h.child.phase != childConsumed && h.child.phase != childUnused || h.child.uncertain) || h.frontend == nil || !h.frontend.withdrawn {
			h.uncertain = true
			return h.fail(ErrUnavailable)
		}
		if h.finishLaunchHistory() != nil {
			h.uncertain = true
			return h.fail(ErrUnavailable)
		}
	}
	for _, f := range []*heldFile{h.lifetime, h.historyDir, h.lock} {
		if f != nil && !f.closed && f.close() != nil {
			h.uncertain = true
			return h.fail(ErrUnavailable)
		}
	}
	if h.cause != nil {
		return ErrUnavailable
	}
	return nil
}
