// SPDX-License-Identifier: BSD-3-Clause
package spike

import (
	"errors"
	"io"
	"os"
	"syscall"
)

type labInputFile interface {
	io.Reader
	io.Closer
	Stat() (os.FileInfo, error)
}

// ReadLabFile admits an opened, bounded regular input. This owned-fixture helper
// does not authenticate parent directories or protect against same-UID writers.
func ReadLabFile(path string, limit int) ([]byte, error) {
	return readLabFile(path, limit, func(name string, flags int) (labInputFile, error) {
		return os.OpenFile(name, flags, 0)
	})
}

func readLabFile(path string, limit int, open func(string, int) (labInputFile, error)) (data []byte, err error) {
	if limit <= 0 || limit == int(^uint(0)>>1) {
		return nil, errors.New("invalid lab file bound")
	}
	file, err := open(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK)
	if err != nil {
		return nil, err
	}
	defer func() {
		err = errors.Join(err, file.Close())
		if err != nil {
			data = nil
		}
	}()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > int64(limit) {
		return nil, errors.New("lab file must be bounded regular input")
	}
	data, err = io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > limit {
		return nil, errors.New("lab file read/bound")
	}
	return data, nil
}
