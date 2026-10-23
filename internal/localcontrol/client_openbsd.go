//go:build openbsd && (amd64 || arm64) && aegvium_service_source

// SPDX-License-Identifier: BSD-3-Clause
package localcontrol

import (
	"bytes"
	"time"

	"golang.org/x/sys/unix"
)

const nativeServiceQualified = false

var clientAttempted bool
var retainedClientFD = -1

// ModeSource reads only the fixed commissioned nonsecret profile. It neither
// infers a profile from absent files nor changes any owner or service state.
func ModeSource() (string, error) {
	if !nativeServiceQualified || clientAttempted || !root() {
		return "", ErrUnavailable
	}
	clientAttempted = true
	return readMode()
}
func readMode() (mode string, out error) {
	for _, name := range []string{"/", "/etc", "/etc/aegvium"} {
		var s unix.Stat_t
		if unix.Lstat(name, &s) != nil || s.Mode&unix.S_IFMT != unix.S_IFDIR || s.Uid != 0 || s.Gid != 0 || s.Mode&0022 != 0 {
			return "", ErrUnavailable
		}
	}
	const path = "/etc/aegvium/frontend-mode"
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return "", ErrUnavailable
	}
	retainedClientFD = fd
	defer func() {
		if unix.Close(fd) != nil {
			mode, out = "", ErrUnavailable
		} else {
			retainedClientFD = -1
		}
	}()
	if fd < 3 {
		return "", ErrUnavailable
	}
	var before, after, named unix.Stat_t
	if unix.Fstat(fd, &before) != nil || before.Mode != unix.S_IFREG|0600 || before.Uid != 0 || before.Gid != 0 || before.Nlink != 1 || (before.Size != 8 && before.Size != 9) {
		return "", ErrUnavailable
	}
	var a, b [10]byte
	n, e := unix.Pread(fd, a[:], 0)
	m, e2 := unix.Pread(fd, b[:], 0)
	if e != nil || e2 != nil || n != int(before.Size) || m != n || !bytes.Equal(a[:n], b[:m]) ||
		unix.Fstat(fd, &after) != nil || unix.Lstat(path, &named) != nil || !modeFacts(before, after) || !modeFacts(before, named) {
		return "", ErrUnavailable
	}
	if string(a[:n]) != "bundled\n" && string(a[:n]) != "external\n" {
		return "", ErrUnavailable
	}
	return string(a[:n]), nil
}

// QuerySource cannot enable operations; its entry gate is immutable false.
// A STOP reply is only cancellation acceptance and NEVER successful retirement.
func QuerySource(owner, verb string) (string, error) {
	if !nativeServiceQualified {
		return "", ErrUnavailable
	}
	return query(owner, verb)
}

func query(owner, verb string) (string, error) {
	if clientAttempted || !root() || !namespace() {
		return "", ErrUnavailable
	}
	clientAttempted = true
	request := Status
	if verb == "stop" {
		request = Stop
	} else if verb != "status" {
		return "", ErrUnavailable
	}
	return exchange(owner, request, time.Now().Add(time.Second), false)
}

// StopAllSource submits both selected one-way commands before cleanup waiting.
// The returned scalar is timing data only, not an ACK or reclamation proof.
func StopAllSource() (int64, error) {
	if !nativeServiceQualified || clientAttempted || !root() || !namespace() {
		return 0, ErrUnavailable
	}
	clientAttempted = true
	mode, e := readMode()
	if e != nil || retainedClientFD >= 0 {
		return 0, ErrUnavailable
	}
	sample := time.Now()
	origin, e := KernelMillisSource()
	if e != nil {
		return 0, e
	}
	request, e := StopRequest(origin)
	if e != nil {
		return 0, e
	}
	end := sample.Add(100 * time.Millisecond)
	owners := []string{"inspector"}
	if mode == "bundled\n" {
		owners = []string{"frontend", "inspector"}
	}
	failed := false
	for _, owner := range owners {
		if retainedClientFD >= 0 {
			return 0, ErrUnavailable
		}
		if _, e := exchange(owner, request, end, true); e != nil {
			failed = true
		}
	}
	if failed {
		return 0, ErrUnavailable
	}
	return origin, nil
}
func exchange(owner, request string, end time.Time, oneway bool) (reply string, out error) {
	if !root() || !namespace() || retainedClientFD >= 0 {
		return "", ErrUnavailable
	}
	path := inspectorPath
	if owner == "frontend" {
		path = frontendPath
	} else if owner != "inspector" {
		return "", ErrUnavailable
	}
	var before, current unix.Stat_t
	if unix.Lstat(path, &before) != nil || !socketKind(before) {
		return "", ErrUnavailable
	}
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		return "", ErrUnavailable
	}
	retainedClientFD = fd
	defer func() {
		if unix.Close(fd) != nil {
			reply, out = "", ErrUnavailable
		} else {
			retainedClientFD = -1
		}
	}()
	if fd < 3 {
		return "", ErrUnavailable
	}
	err = unix.Connect(fd, &unix.SockaddrUnix{Name: path})
	if err != nil && err != unix.EINPROGRESS && err != unix.EAGAIN {
		return "", ErrUnavailable
	}
	for err != nil && time.Now().Before(end) {
		var poll = []unix.PollFd{{Fd: int32(fd), Events: unix.POLLOUT}}
		n, e := unix.Poll(poll, 0)
		if e != nil && e != unix.EINTR {
			return "", ErrUnavailable
		}
		if n > 0 {
			code, e := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ERROR)
			if e != nil || code != 0 {
				return "", ErrUnavailable
			}
			err = nil
		} else {
			time.Sleep(time.Millisecond)
		}
	}
	uid, gid, e := peerIdentity(fd)
	if err != nil || e != nil || uid != 0 || gid != 0 || !namespace() || unix.Lstat(path, &current) != nil || !sameSocket(before, current) {
		return "", ErrUnavailable
	}
	first := true
	for sent := 0; sent < len(request); {
		if !time.Now().Before(end) && !(oneway && first) {
			return "", ErrUnavailable
		}
		first = false
		n, e := unix.SendmsgN(fd, []byte(request[sent:]), nil, nil, unix.MSG_NOSIGNAL|unix.MSG_DONTWAIT)
		if e == unix.EAGAIN || e == unix.EWOULDBLOCK || e == unix.EINTR {
			time.Sleep(time.Millisecond)
			continue
		}
		if e != nil || n <= 0 {
			return "", ErrUnavailable
		}
		sent += n
	}
	if unix.Shutdown(fd, unix.SHUT_WR) != nil {
		return "", ErrUnavailable
	}
	if oneway {
		if !namespace() || unix.Lstat(path, &current) != nil || !sameSocket(before, current) {
			return "", ErrUnavailable
		}
		return "", nil // no reply is part of AGCTL2; defer owns the one close
	}
	var raw [65]byte
	used := 0
	for time.Now().Before(end) {
		n, e := unix.Read(fd, raw[used:])
		if e == unix.EAGAIN || e == unix.EWOULDBLOCK || e == unix.EINTR {
			time.Sleep(time.Millisecond)
			continue
		}
		if e != nil {
			return "", ErrUnavailable
		}
		used += n
		if used == len(raw) {
			return "", ErrUnavailable
		}
		if n == 0 {
			if !ValidReply(owner, raw[:used]) || !namespace() || unix.Lstat(path, &current) != nil || !sameSocket(before, current) {
				return "", ErrUnavailable
			}
			if request == Stop {
				want, _ := Reply(owner, "retiring")
				if string(raw[:used]) != want {
					return "", ErrUnavailable
				}
			}
			return string(raw[:used]), nil
		}
	}
	return "", ErrUnavailable
}

func modeFacts(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode && a.Uid == b.Uid && a.Gid == b.Gid && a.Nlink == b.Nlink && a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}
