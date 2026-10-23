//go:build openbsd && (amd64 || arm64) && (aegvium_frontend_source || aegvium_service_source)

// SPDX-License-Identifier: BSD-3-Clause
package localcontrol

import (
	"os"
	"time"

	"golang.org/x/sys/unix"
)

const directory = "/var/run/aegvium"
const frontendPath = directory + "/frontend.sock"
const inspectorPath = directory + "/inspector.sock"

func root() bool {
	return os.Getuid() == 0 && os.Geteuid() == 0 && os.Getgid() == 0 && os.Getegid() == 0
}
func ancestors() bool {
	for _, name := range []string{"/", "/var", "/var/run"} {
		var st unix.Stat_t
		if unix.Lstat(name, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != 0 || st.Gid != 0 || st.Mode&0022 != 0 {
			return false
		}
	}
	return true
}
func namespace() bool {
	var st unix.Stat_t
	return ancestors() && unix.Lstat(directory, &st) == nil && st.Mode == unix.S_IFDIR|0700 && st.Uid == 0 && st.Gid == 0
}
func socketKind(st unix.Stat_t) bool {
	return st.Mode == unix.S_IFSOCK|0600 && st.Uid == 0 && st.Gid == 0 && st.Nlink == 1
}
func sameSocket(a, b unix.Stat_t) bool {
	return socketKind(a) && socketKind(b) && a.Dev == b.Dev && a.Ino == b.Ino
}

// Frontend is used only by the existing frontend owner. It owns one listener
// and at most one client; no goroutine, callback or serving capability exists.
type Frontend struct {
	fd, client                 int
	stat                       unix.Stat_t
	request                    [33]byte
	used, sent                 int
	reply                      string
	end                        time.Time
	origin                     int64
	stopped, uncertain, closed bool
}

func OpenFrontendSource() (*Frontend, error) {
	if frontendAttempted || !root() {
		return nil, ErrUnavailable
	}
	frontendAttempted = true
	if !ancestors() {
		return nil, ErrUnavailable
	}
	if err := unix.Mkdir(directory, 0700); err != nil && err != unix.EEXIST {
		return nil, ErrUnavailable
	}
	if !namespace() {
		return nil, ErrUnavailable
	}
	var old unix.Stat_t
	if unix.Lstat(frontendPath, &old) != unix.ENOENT {
		return nil, ErrUnavailable // never dispose of an existing/stale endpoint
	}
	f := &Frontend{fd: -1, client: -1}
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		return nil, ErrUnavailable
	}
	f.fd = fd
	// Keep this actual owner on failure; uncertain close is not retried.
	retainedFrontend = f
	if fd < 3 {
		f.closed = true
		if unix.Close(fd) != nil {
			f.uncertain = true
		} else {
			f.fd = -1
		}
		return f, ErrUnavailable
	}
	if unix.Bind(fd, &unix.SockaddrUnix{Name: frontendPath}) != nil || unix.Chmod(frontendPath, 0600) != nil ||
		unix.Lstat(frontendPath, &f.stat) != nil || !socketKind(f.stat) || !namespace() || unix.Listen(fd, 1) != nil {
		f.uncertain = true
		return f, ErrUnavailable
	}
	return f, nil
}

var retainedFrontend *Frontend
var frontendAttempted bool

func (f *Frontend) drop() error {
	fd := f.client
	if fd < 0 {
		return nil
	}
	if unix.Close(fd) != nil {
		f.uncertain = true
		return ErrUnavailable
	}
	f.client, f.used, f.sent, f.reply = -1, 0, 0, ""
	return nil
}

// Poll performs at most one accept, one read and one send, all nonblocking.
// Invalid/stalled clients never enter the child owner; only exact root STOP
// latches cancellation. It never resets a retirement deadline or reads a journal.
func (f *Frontend) Poll(phase string) (bool, error) {
	if f == nil || f.closed || f.uncertain || f.fd < 0 {
		return false, ErrUnavailable
	}
	var current unix.Stat_t
	if !namespace() || unix.Lstat(frontendPath, &current) != nil || !sameSocket(f.stat, current) {
		f.uncertain = true
		return false, ErrUnavailable
	}
	if f.client < 0 {
		fd, err := acceptLocal(f.fd, unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK)
		if err == unix.EAGAIN || err == unix.EWOULDBLOCK || err == unix.EINTR {
			return f.stopped, nil
		}
		if err != nil {
			f.uncertain = true
			return false, ErrUnavailable
		}
		f.client, f.end = fd, time.Now().Add(time.Second)
		if fd < 3 {
			return f.stopped, f.drop()
		}
		uid, gid, err := peerIdentity(fd)
		if err != nil || uid != 0 || gid != 0 {
			return f.stopped, f.drop()
		}
	}
	if !time.Now().Before(f.end) {
		return f.stopped, f.drop()
	}
	if f.reply == "" {
		n, err := unix.Read(f.client, f.request[f.used:])
		if err == unix.EAGAIN || err == unix.EWOULDBLOCK || err == unix.EINTR {
			return f.stopped, nil
		}
		if err != nil {
			return f.stopped, f.drop()
		}
		f.used += n
		if f.used == len(f.request) {
			return f.stopped, f.drop()
		}
		if n != 0 {
			return f.stopped, nil
		} // exact EOF is mandatory
		stop, origin, err := ParseRequest(f.request[:f.used], 0, 0)
		if err != nil {
			return f.stopped, f.drop()
		}
		oneway := origin > 0
		if stop {
			now, e := KernelMillisSource()
			if e != nil {
				f.uncertain = true
				return f.stopped, ErrUnavailable
			}
			if origin > now {
				return f.stopped, f.drop()
			}
			if origin == 0 {
				origin = now
			}
			if origin <= 0 {
				f.uncertain = true
				return f.stopped, ErrUnavailable
			}
			if !f.stopped || origin < f.origin {
				f.origin = origin
			}
		}
		f.stopped = f.stopped || stop
		if oneway {
			return f.stopped, f.drop()
		}
		if f.stopped {
			phase = "retiring"
		}
		f.reply, err = Reply("frontend", phase)
		if err != nil {
			f.uncertain = true
			return f.stopped, ErrUnavailable
		}
	}
	n, err := unix.SendmsgN(f.client, []byte(f.reply[f.sent:]), nil, nil, unix.MSG_DONTWAIT|unix.MSG_NOSIGNAL)
	if err == unix.EAGAIN || err == unix.EWOULDBLOCK || err == unix.EINTR {
		return f.stopped, nil
	}
	if err != nil || n <= 0 {
		return f.stopped, f.drop()
	}
	f.sent += n
	if f.sent == len(f.reply) {
		return f.stopped, f.drop()
	}
	return f.stopped, nil
}

// Close is called only after actual original-child terminal/no-birth. Its known
// closure precedes normal C settlement. Unknown closure retains the path/owner.
func (f *Frontend) Close() error {
	if f == nil || f.closed || f.uncertain {
		return ErrUnavailable
	}
	f.closed = true
	if f.drop() != nil {
		return ErrUnavailable
	}
	if unix.Close(f.fd) != nil {
		f.uncertain = true
		return ErrUnavailable
	}
	f.fd = -1
	var current unix.Stat_t
	if !namespace() || unix.Lstat(frontendPath, &current) != nil || !sameSocket(f.stat, current) || unix.Unlink(frontendPath) != nil {
		f.uncertain = true
		return ErrUnavailable
	}
	return nil
}

// StopOrigin is derived only from a canonical root request on this owner's own
// accepted connection. Repeated commands can shorten, never renew, the budget.
func (f *Frontend) StopOrigin() (time.Time, error) {
	if f == nil || !f.stopped {
		return time.Time{}, ErrUnavailable
	}
	sample := time.Now()
	now, e := KernelMillisSource()
	if e != nil {
		return time.Time{}, e
	}
	return ConservativeOrigin(sample, f.origin, now)
}

func (f *Frontend) StoppedSource() bool { return f != nil && f.stopped }
