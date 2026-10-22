//go:build openbsd && aegvium_transport_source

// SPDX-License-Identifier: BSD-3-Clause
package requestctx

import (
	"os"
	"sync"
	"syscall"
	"time"
)

var inheritedPairProcess struct {
	sync.Mutex
	attempted bool
	owner     *inheritedPairBootstrap
}

// Hold the one actual os.File so its finalizer cannot close a forgotten FD.
// Bootstrap uses raw nonblocking Read, not os.File's poll/retry path. No method
// exposes the FD or creates another file/connection for the persistent channel.
type fixedPairFD3 struct{ file *os.File }

func (f *fixedPairFD3) Read(p []byte) (int, error) { return syscall.Read(3, p) }

// Source only: no installed caller exists. FD shape and the returned object
// establish neither supervisor identity nor trusted fork/exec provenance.
func acquireInheritedPairFD3() (owner *inheritedPairBootstrap, err error) {
	inheritedPairProcess.Lock()
	if inheritedPairProcess.attempted {
		inheritedPairProcess.Unlock()
		return nil, errPair
	}
	inheritedPairProcess.attempted = true
	owner = &inheritedPairBootstrap{}
	inheritedPairProcess.owner = owner
	inheritedPairProcess.Unlock()
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
	file := os.NewFile(3, "aegvium-inherited-control")
	owner.endpoint = &fixedPairFD3{file: file}
	if file == nil {
		return owner, errPair
	}
	// In the pinned Go runtime, NewFile's actual F_GETFL must observe
	// O_NONBLOCK before kindNewFile can register with the poller. A failed
	// query or blocking descriptor is not pollable and returns ErrNoDeadline.
	// This clears no OS flag and performs no polling Read; the runtime/kqueue
	// registration remains part of the unqualified inspector syscall closure.
	if file.SetReadDeadline(time.Time{}) != nil {
		return owner, errPair
	}
	stat, statErr := file.Stat()
	typ, typeErr := syscall.GetsockoptInt(3, syscall.SOL_SOCKET, syscall.SO_TYPE)
	peer, peerErr := syscall.Getpeername(3)
	if statErr != nil || stat.Mode()&os.ModeSocket == 0 || typeErr != nil || typ != syscall.SOCK_STREAM || peerErr != nil {
		return owner, errPair
	}
	if _, ok := peer.(*syscall.SockaddrUnix); !ok {
		return owner, errPair
	}
	complete = true
	return owner, nil
}

// The trusted real-launch entry is still unissued. A local match prepares only
// the same-channel configuration; it deliberately constructs no TLS receiver.
func prepareInheritedPairSnapshot(descriptor []byte) error {
	owner, err := acquireInheritedPairFD3()
	if err != nil {
		return errPair
	}
	return owner.consume(descriptor)
}
