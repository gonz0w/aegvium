//go:build openbsd && (amd64 || arm64) && (aegvium_frontend_source || aegvium_service_source)

// Go Authors BSD trampoline pattern adapted from x/sys v0.49.0 and private
// Vectivium source; complete notices are in LICENSE.x-sys/LICENSE.Vectivium.
package localcontrol

import (
	"runtime"
	"syscall"
	"unsafe"
)

//go:linkname callLibc syscall.syscall
func callLibc(fn, a1, a2, a3 uintptr) (r1, r2 uintptr, err syscall.Errno)

//go:linkname callLibc6 syscall.syscall6
func callLibc6(fn, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, err syscall.Errno)

var peerTrampoline, acceptTrampoline uintptr

//go:cgo_import_dynamic aeg_service_getpeereid getpeereid "libc.so"
//go:cgo_import_dynamic aeg_service_accept4 accept4 "libc.so"

func peerIdentity(fd int) (uid, gid uint32, err error) {
	uid, gid = ^uint32(0), ^uint32(0)
	_, _, e := callLibc(peerTrampoline, uintptr(fd), uintptr(unsafe.Pointer(&uid)), uintptr(unsafe.Pointer(&gid)))
	runtime.KeepAlive(&uid)
	runtime.KeepAlive(&gid)
	if e != 0 {
		return uid, gid, e
	}
	return uid, gid, nil
}

func acceptLocal(fd, flags int) (int, error) {
	n, _, e := callLibc6(acceptTrampoline, uintptr(fd), 0, 0, uintptr(flags), 0, 0)
	if e != 0 {
		return -1, e
	}
	return int(n), nil
}
