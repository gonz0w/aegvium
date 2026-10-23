//go:build openbsd && aegvium_transport_source && aegvium_engine_source && no_fs_access

// SPDX-License-Identifier: BSD-3-Clause
package bodyowner

import (
	"os"
	"syscall"
)

// Fixed inherited fd2 only. No socket creation, path, destination, duplication,
// poller write, retry, flush, callback or additional worker exists in I.
type sourceDiagnostics struct {
	file     *os.File // Retain the original descriptor through process exit.
	sequence diagnosticSequence
	usable   bool
}

func acquireDiagnosticsSource() (d sourceDiagnostics) {
	d.file = os.NewFile(2, "aegvium-inherited-diagnostics")
	if d.file == nil {
		return d
	}
	flags, _, flagErr := syscall.Syscall(syscall.SYS_FCNTL, 2, syscall.F_GETFL, 0)
	typ, typeErr := syscall.GetsockoptInt(2, syscall.SOL_SOCKET, syscall.SO_TYPE)
	peer, peerErr := syscall.Getpeername(2)
	_, unix := peer.(*syscall.SockaddrUnix)
	d.usable = flagErr == 0 && flags&syscall.O_NONBLOCK != 0 && typeErr == nil && typ == syscall.SOCK_DGRAM && peerErr == nil && unix
	return d // Shape is not authenticated launch or diagnostic durability proof.
}

func (s *InspectorEngineSource) drainDiagnosticsSource() {
	v := s.owner.takeDiagnostics()
	for i := 0; i < v.n; i++ {
		s.owner.state.mu.Lock()
		stopped := s.owner.state.stopped
		s.owner.state.mu.Unlock()
		if stopped {
			s.owner.loseDiagnostics(v.n - i)
			return
		}
		p, ok := s.diagnostics.sequence.frame(v, v.events[i])
		if !ok || !s.diagnostics.usable {
			s.owner.loseDiagnostics(1)
			continue
		}
		// At most one committed send may race Stop. No send after observed stop.
		n, err := syscall.SendmsgN(2, p[:], nil, nil, syscall.MSG_DONTWAIT|syscall.MSG_NOSIGNAL)
		if err != nil || n != len(p) {
			s.owner.loseDiagnostics(1)
		}
	}
}
