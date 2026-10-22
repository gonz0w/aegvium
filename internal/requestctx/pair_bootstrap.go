//go:build aegvium_transport_source

// SPDX-License-Identifier: BSD-3-Clause
package requestctx

import (
	"bytes"
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
func (b *inheritedPairBootstrap) consume(descriptor []byte) (err error) {
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
	snapshot, parseErr := newPairedSnapshot(descriptor)
	if parseErr != nil || endpoint == nil {
		return errPair
	}
	var frame [104]byte
	n, readErr := endpoint.Read(frame[:])
	if readErr != nil || n != len(frame) || !bytes.Equal(frame[:], snapshot.tuple[:]) {
		return errPair
	}
	b.mu.Lock()
	b.snapshot = snapshot // Configuration equality only, never S identity.
	b.mu.Unlock()
	complete = true
	return nil
}
