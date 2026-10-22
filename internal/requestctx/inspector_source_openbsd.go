//go:build openbsd && aegvium_transport_source

// SPDX-License-Identifier: BSD-3-Clause
package requestctx

import (
	"bytes"
	stdhex "encoding/hex"
	"io"
	"os"
	"sort"
	"sync"
	"syscall"
	"time"
)

const inspectorRoleDirectory = "/etc/aegvium/inspector"

// InspectorSource owns the actual inherited channel and its role-local material.
// It grants no Ready, supervisor identity, serving, or reclamation authority.
// Failed preparation remains process-owned; there is no reset or retry issuer.
type InspectorSource struct {
	mu                                                     sync.Mutex
	bootstrap                                              *inheritedPairBootstrap
	channel                                                *os.File
	receiver                                               *pairReceiver
	materials                                              pairMaterials
	directories                                            []*inspectorSourceFile
	reads                                                  []*inspectorSourceFile
	root                                                   *os.Root
	rootCloseTried                                         bool
	prepared, uncertain                                    bool
	confirmTried, confirmed, controlClaimed, controlClosed bool
}

type inspectorSourceFile struct {
	file            *os.File
	info            os.FileInfo
	path            string
	first, readback []byte
	closeTried      bool
}

var inspectorSourceProcess struct {
	sync.Mutex
	attempted bool
	owner     *InspectorSource
}

// PrepareInspectorSource is the only source constructor. It consumes actual FD3
// once, reads no caller paths, obtains no ambient roots, and parses credentials
// only in this source-tagged production path. Tests must not call it.
func PrepareInspectorSource() (owner *InspectorSource, err error) {
	inspectorSourceProcess.Lock()
	if inspectorSourceProcess.attempted {
		inspectorSourceProcess.Unlock()
		return nil, errPair
	}
	inspectorSourceProcess.attempted = true
	owner = &InspectorSource{}
	inspectorSourceProcess.owner = owner
	inspectorSourceProcess.Unlock()
	complete := false
	defer func() {
		if !complete {
			_ = recover()
			owner.mu.Lock()
			owner.uncertain = true
			owner.mu.Unlock()
			err = errPair
		}
	}()
	// These observations require the real launcher to have dropped identities;
	// they do not authenticate that launcher or create an account.
	uid, gid := os.Getuid(), os.Getgid()
	groups, groupErr := os.Getgroups()
	if uid == 0 || gid == 0 || uid != os.Geteuid() || gid != os.Getegid() || groupErr != nil || len(groups) != 0 {
		return owner, errPair
	}
	bootstrap, acquireErr := acquireInheritedPairFD3()
	owner.bootstrap = bootstrap
	if bootstrap != nil {
		if endpoint, ok := bootstrap.endpoint.(*fixedPairFD3); ok {
			owner.channel = endpoint.file
		}
	}
	if acquireErr != nil || bootstrap == nil || owner.channel == nil || bootstrap.consume() != nil {
		return owner, errPair
	}
	owner.materials.descriptor = bootstrap.descriptor
	readErr := owner.readRoleMaterial(gid)
	closeErr := owner.closeRoleMaterial()
	if readErr != nil || closeErr != nil {
		return owner, errPair
	}
	owner.receiver, err = newPairReceiver(owner.materials)
	if err != nil || owner.receiver == nil {
		return owner, errPair
	}
	owner.prepared = true
	complete = true
	return owner, nil
}

func (s *InspectorSource) checkDirectories() bool {
	for _, held := range s.directories {
		named, err := os.Lstat(held.path)
		current, statErr := held.file.Stat()
		if err != nil || statErr != nil || !inspectorDirectory(named) || !inspectorSame(held.info, named) || !inspectorSame(held.info, current) {
			return false
		}
	}
	return true
}

func (s *InspectorSource) readRoleMaterial(gid int) error {
	for _, path := range []string{"/", "/etc", "/etc/aegvium", inspectorRoleDirectory} {
		held := &inspectorSourceFile{path: path}
		s.directories = append(s.directories, held)
		file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		held.file = file
		if err != nil || file == nil {
			return errPair
		}
		held.info, err = file.Stat()
		if err != nil || !inspectorDirectory(held.info) || !s.checkDirectories() {
			return errPair
		}
	}
	root, err := os.OpenRoot(inspectorRoleDirectory)
	s.root = root
	if err != nil || root == nil {
		return errPair
	}
	// Bind Root's directory handle to the already checked nonsymlink directory.
	bound := &inspectorSourceFile{}
	s.reads = append(s.reads, bound)
	bound.file, err = root.OpenFile(".", os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil || bound.file == nil {
		return errPair
	}
	bound.info, err = bound.file.Stat()
	if err != nil || !inspectorSame(s.directories[len(s.directories)-1].info, bound.info) {
		return errPair
	}
	if s.materials.certificatePEM, err = s.readRoleFile("cert.pem", 65536, gid); err != nil {
		return errPair
	}
	if s.materials.privateKeyPEM, err = s.readRoleFile("key.pem", 16384, gid); err != nil {
		return errPair
	}
	if s.materials.serverRootDER, err = s.readRoleFile("server.der", 16384, gid); err != nil {
		return errPair
	}
	anchors := s.bootstrap.snapshot.anchors
	if len(anchors) < 1 || len(anchors) > 8 {
		return errPair
	}
	names := make([]string, 0, len(anchors))
	for pin := range anchors {
		names = append(names, "client-"+stdhex.EncodeToString(pin[:])+".der")
	}
	sort.Strings(names)
	for _, name := range names {
		material, err := s.readRoleFile(name, 16384, gid)
		if err != nil {
			return errPair
		}
		s.materials.clientRootDER = append(s.materials.clientRootDER, material)
	}
	if !s.checkDirectories() {
		return errPair
	}
	return nil
}

func (s *InspectorSource) readRoleFile(name string, limit, gid int) ([]byte, error) {
	if !s.checkDirectories() {
		return nil, errPair
	}
	held := &inspectorSourceFile{path: name}
	s.reads = append(s.reads, held)
	file, err := s.root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	held.file = file
	if err != nil || file == nil {
		return nil, errPair
	}
	held.info, err = file.Stat()
	_, ok := inspectorStat(held.info)
	if err != nil || !ok || !inspectorRoleFile(held.info, limit, gid) {
		return nil, errPair
	}
	current := func() bool {
		named, nameErr := s.root.Lstat(name)
		fd, statErr := file.Stat()
		return nameErr == nil && statErr == nil && inspectorSame(held.info, named) && inspectorSame(held.info, fd) && s.checkDirectories()
	}
	if !current() {
		return nil, errPair
	}
	held.first, held.readback = make([]byte, limit+1), make([]byte, limit+1)
	n, readErr := file.ReadAt(held.first, 0)
	if readErr != io.EOF || n != int(held.info.Size()) || !current() {
		return nil, errPair
	}
	m, rereadErr := file.ReadAt(held.readback, 0)
	if rereadErr != io.EOF || m != n || !bytes.Equal(held.first[:n], held.readback[:m]) || !current() {
		return nil, errPair
	}
	return held.first[:n], nil
}

// Every created handle receives at most one Close attempt. A failed Close is
// retained, never retried and never interpreted as physical cleanup proof.
func (s *InspectorSource) closeRoleMaterial() error {
	failed := false
	for _, list := range [][]*inspectorSourceFile{s.reads, s.directories} {
		for i := len(list) - 1; i >= 0; i-- {
			held := list[i]
			if held.file != nil && !held.closeTried {
				held.closeTried = true
				if held.file.Close() != nil {
					failed = true
				}
			}
		}
	}
	if s.root != nil && !s.rootCloseTried {
		s.rootCloseTried = true
		if s.root.Close() != nil {
			failed = true
		}
	}
	if failed {
		return errPair
	}
	return nil
}

// Generation returns configuration data only; it is not launch authority.
func (s *InspectorSource) Generation() string {
	if s == nil {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.prepared || s.uncertain {
		return ""
	}
	return string(s.bootstrap.snapshot.tuple[8:40])
}

// PolicyPinSource requires every route to select this one engine profile. It is
// configuration equality only; the engine constructor checks its actual pin.
func (s *InspectorSource) PolicyPinSource() string {
	if s == nil {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.prepared || s.uncertain {
		return ""
	}
	return inspectorPolicyPin(s.bootstrap.snapshot)
}

// ConfirmPreparedSource must be called by the top startup owner AFTER engine
// initialization. This bounded same-channel diagnostic cannot establish that
// ordering itself, S identity, Ready, service availability, or cleanup.
func (s *InspectorSource) ConfirmPreparedSource() (err error) {
	if s == nil {
		return errPair
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.confirmTried {
		return errPair
	}
	s.confirmTried = true
	complete := false
	defer func() {
		if !complete {
			_ = recover()
			s.uncertain = true
			err = errPair
		}
	}()
	if !s.prepared || s.uncertain || s.channel == nil || s.controlClaimed {
		return errPair
	}
	frame := inspectorPreparedFrame(s.bootstrap.snapshot.tuple)
	deadline := time.Now().Add(2 * time.Second)
	if s.channel.SetWriteDeadline(deadline) != nil {
		return errPair
	}
	n, writeErr := s.channel.Write(frame[:])
	if writeErr != nil || n != len(frame) || !time.Now().Before(deadline) {
		return errPair
	}
	if s.channel.SetWriteDeadline(time.Time{}) != nil || !time.Now().Before(deadline) {
		return errPair
	}
	s.confirmed = true
	complete = true
	return nil
}

// ClaimControlSource transfers only access to the SAME retained os.File, once.
// Confirmation precedes this handoff to prevent startup/retirement write races.
// No FD getter, FileConn, descriptor duplication or reopen is provided.
func (s *InspectorSource) ClaimControlSource() (io.ReadWriteCloser, error) {
	if s == nil {
		return nil, errPair
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.controlClaimed {
		return nil, errPair
	}
	s.controlClaimed = true
	if !s.prepared || s.uncertain || !s.confirmed || s.channel == nil {
		return nil, errPair
	}
	return &inspectorSourceControl{owner: s}, nil
}

type inspectorSourceControl struct{ owner *InspectorSource }

func (c *inspectorSourceControl) Read(p []byte) (int, error)  { return c.owner.channel.Read(p) }
func (c *inspectorSourceControl) Write(p []byte) (int, error) { return c.owner.channel.Write(p) }
func (c *inspectorSourceControl) Close() error {
	s := c.owner
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.controlClosed {
		return errPair
	}
	s.controlClosed = true
	if s.channel.Close() != nil {
		s.uncertain = true
		return errPair
	}
	return nil
}
