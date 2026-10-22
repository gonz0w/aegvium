// SPDX-License-Identifier: BSD-3-Clause
package commissionplace

import (
	"os"
	"syscall"
)

func infoSys(info os.FileInfo) (*syscall.Stat_t, bool) {
	if info == nil {
		return nil, false
	}
	s, ok := info.Sys().(*syscall.Stat_t)
	return s, ok && s != nil
}

func placedFile(info os.FileInfo, mode os.FileMode, size int64, gid int) bool {
	s, ok := infoSys(info)
	return ok && gid >= 0 && uint64(gid) < 4294967295 && info.Mode().IsRegular() &&
		s.Uid == 0 && s.Gid == uint32(gid) && s.Nlink == 1 && uint32(s.Mode)&07777 == uint32(mode) && info.Size() == size
}
