//go:build aegvium_transport_source

// SPDX-License-Identifier: BSD-3-Clause
package requestctx

import (
	"os"
	"syscall"
)

func inspectorStat(info os.FileInfo) (*syscall.Stat_t, bool) {
	if info == nil {
		return nil, false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	return st, ok && st != nil
}

func inspectorSame(a, b os.FileInfo) bool {
	x, ok := inspectorStat(a)
	y, other := inspectorStat(b)
	return ok && other && os.SameFile(a, b) && x.Mode == y.Mode && x.Uid == y.Uid && x.Gid == y.Gid && x.Nlink == y.Nlink && a.Size() == b.Size()
}

func inspectorDirectory(info os.FileInfo) bool {
	st, ok := inspectorStat(info)
	return ok && info.IsDir() && st.Uid == 0 && st.Gid == 0 && st.Mode&(syscall.S_ISUID|syscall.S_ISGID|syscall.S_ISVTX|0022) == 0
}

// Fixed protected role-file admission, before any bytes are parsed.
func inspectorRoleFile(info os.FileInfo, limit, gid int) bool {
	st, ok := inspectorStat(info)
	return ok && gid > 0 && uint64(gid) < 4294967295 && limit > 0 &&
		info.Mode().IsRegular() && st.Uid == 0 && st.Gid == uint32(gid) &&
		st.Nlink == 1 && st.Mode&07777 == 0440 && info.Size() >= 1 && info.Size() <= int64(limit)
}

func inspectorPreparedFrame(tuple [104]byte) (out [112]byte) {
	copy(out[:8], "AGSTART1")
	copy(out[8:], tuple[:])
	return
}

func inspectorPolicyPin(s *pairedSnapshot) string {
	if s == nil || s.context == nil {
		return ""
	}
	s.context.mu.Lock()
	defer s.context.mu.Unlock()
	if s.context.retired || len(s.context.routes) < 1 || len(s.context.routes) > 8 {
		return ""
	}
	pin := ""
	for _, r := range s.context.routes {
		if !hex(r.pin, 64) || pin != "" && pin != r.pin {
			return ""
		}
		pin = r.pin
	}
	return pin
}
