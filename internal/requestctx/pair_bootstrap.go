//go:build aegvium_transport_source

// SPDX-License-Identifier: BSD-3-Clause
package requestctx

import (
	"bytes"
	"encoding/binary"
	"io"
	"sync"
)

// Private staging state, NOT a launch-authority capability. Its only production
// source is the fixed inherited-FD acquisition. Neither a successful read nor
// this snapshot can call newPairReceiver, create a Peer, or authorize serving.
type inheritedPairBootstrap struct {
	mu        sync.Mutex
	endpoint  io.Reader
	claimed   bool
	uncertain bool
	snapshot  *pairedSnapshot
}

// Keep the same endpoint on every outcome for the future sole-launch/control
// composition. This function never duplicates, reopens, closes or refunds it.
// Production reads are one raw nonblocking FD3 read, without a polling worker.
func (b *inheritedPairBootstrap) consume() (err error) {
	if b == nil {
		return errPair
	}
	b.mu.Lock()
	if b.claimed {
		b.mu.Unlock()
		return errPair
	}
	b.claimed = true
	endpoint := b.endpoint
	b.mu.Unlock()

	complete := false
	defer func() {
		if !complete {
			_ = recover()
			b.mu.Lock()
			b.uncertain = true
			b.mu.Unlock()
			err = errPair
		}
	}()
	if endpoint == nil {
		return errPair
	}
	// Distinct outer magic prevents an old104-byte consumer from accepting a
	// prefix and leaving the new descriptor unread. The extra byte rejects
	// oversized input; no caller supplies descriptor bytes or a provider.
	var frame [8307]byte
	n, readErr := endpoint.Read(frame[:])
	if readErr != nil || n < 161 || n > 8306 || string(frame[:8]) != "AGBOOT1\n" {
		return errPair
	}
	size := int(binary.BigEndian.Uint16(frame[8:10]))
	if size < 47 || size > 8192 || n != 114+size || string(frame[18:50]) == "00000000000000000000000000000000" {
		return errPair
	}
	snapshot, parseErr := newPairedSnapshot(frame[114:n])
	if parseErr != nil || !bytes.Equal(frame[10:114], snapshot.tuple[:]) {
		return errPair
	}
	b.mu.Lock()
	b.snapshot = snapshot // Configuration equality only, never S identity.
	b.mu.Unlock()
	complete = true
	return nil
}
