// SPDX-License-Identifier: BSD-3-Clause
package commission

import (
	"bytes"
	"encoding/hex"

	"github.com/gonz0w/aegvium/internal/pairmodel"
)

// InitialFile is fixed first-image data, not freshness or reset authority.
type InitialFile struct {
	Name string
	Data []byte
}

// InitialFiles shares the exact five state members between the staging archive
// and the fixed production initializer. Only a continuously owned fresh target
// may receive them; their bytes cannot establish that lifetime.
func InitialFiles(descriptor []byte, inspector [32]byte) ([]InitialFile, error) {
	d, err := pairmodel.Parse(descriptor)
	if err != nil {
		return nil, ErrPayload
	}
	descriptor = d.Bytes()
	state, err := initialState(descriptor[8:40])
	if err != nil {
		return nil, err
	}
	records := initialRecords(state)
	return []InitialFile{
		{"inspector.pin", []byte(hex.EncodeToString(inspector[:]) + "\n")},
		{"pair.snapshot", descriptor},
		{"launch.intent", append(bytes.Clone(descriptor[8:40]), '\n')},
		{"security.records", bytes.Clone(records[:])},
		{"launch.state", bytes.Clone(state[:])},
	}, nil
}
