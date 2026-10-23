//go:build openbsd && aegvium_frontend_source

// SPDX-License-Identifier: BSD-3-Clause
package frontendowner

import (
	"bytes"
	"io"

	"golang.org/x/sys/unix"
)

func (h *history) lifetimeFacts() (fileFacts, error) {
	if h.lifetime == nil || h.historyDir == nil || h.lifetime.fd() < 3 || h.historyDir.fd() < 3 {
		return fileFacts{}, ErrUnavailable
	}
	var opened, named unix.Stat_t
	if unix.Fstat(h.lifetime.fd(), &opened) != nil || unix.Fstatat(h.historyDir.fd(), "launch.state", &named, unix.AT_SYMLINK_NOFOLLOW) != nil {
		return fileFacts{}, ErrUnavailable
	}
	f := facts(&opened)
	if !protected(f, false, 0600) || f.size != 160 || !sameFile(f, facts(&named)) {
		return fileFacts{}, ErrUnavailable
	}
	return f, nil
}
func (h *history) readLifetime() (raw [160]byte, err error) {
	initial, e := h.lifetimeFacts()
	if e != nil {
		return raw, e
	}
	n, e := h.lifetime.file.ReadAt(raw[:], 0)
	if n != len(raw) || e != nil {
		return raw, ErrUnavailable
	}
	var tail [1]byte
	n, e = h.lifetime.file.ReadAt(tail[:], 160)
	after, e2 := h.lifetimeFacts()
	if n != 0 || e != io.EOF || e2 != nil || !sameFile(initial, after) {
		return raw, ErrUnavailable
	}
	return raw, nil
}
func (h *history) openLifetime() error {
	f, err := h.open(h.historyDir, "launch.state", false, 0600, true)
	if err != nil {
		return err
	}
	h.lifetime = f
	raw, err := h.readLifetime()
	if err != nil {
		return h.fail(err)
	}
	phase, record, ok := parseLifetime(raw)
	if !ok || phase != 'C' {
		h.uncertain = true
		return h.fail(ErrUnavailable)
	}
	h.stateFrame, h.stateRecord, h.initialState = raw, record, record == [104]byte{}
	h.stateFacts, err = h.lifetimeFacts()
	if err != nil {
		return h.fail(err)
	}
	return nil
}

// U precedes the actual fixed-child start attempt; no supplied PID/receipt can
// issue it. It consumes this attempt even on partial writes or sync uncertainty.
func (h *history) beginLaunchHistory() error {
	if h.beginAttempted {
		return h.fail(ErrUnavailable)
	}
	h.beginAttempted = true
	if !h.live() || !h.consumed || !h.frontendLive() || h.child != nil || h.launchCommitted || h.uncertain {
		return h.fail(ErrUnavailable)
	}
	if h.writeLifetime('U', h.record) != nil {
		h.uncertain = true
		return h.fail(ErrUnavailable)
	}
	h.launchCommitted = true
	return nil
}

// This is private terminal settlement after actual original-child wait (or a
// private pre-Start no-birth state) and all
// non-storage handles closed. No journal operation participates in stop/wait.
// Physical cleanup is distinct from target timing and owner-process retirement.
func (h *history) finishLaunchHistory() error {
	if h.cleanAttempted {
		return h.fail(ErrUnavailable)
	}
	h.cleanAttempted = true
	if !h.launchCommitted || h.uncertain || h.child != nil && (h.child.phase != childConsumed && h.child.phase != childUnused || h.child.uncertain) ||
		h.frontend == nil || !h.frontend.withdrawn {
		return h.fail(ErrUnavailable)
	}
	for _, f := range h.files {
		if f != h.lifetime && f != h.historyDir && f != h.lock && !f.closed {
			return h.fail(ErrUnavailable)
		}
	}
	if h.writeLifetime('C', h.record) != nil {
		return h.fail(ErrUnavailable)
	}
	h.launchCommitted = false
	return nil
}

func (h *history) writeLifetime(phase byte, record [104]byte) error {
	old, e := h.readLifetime()
	current, e2 := h.lifetimeFacts()
	if e != nil || e2 != nil || old != h.stateFrame || !sameFile(current, h.stateFacts) {
		return ErrUnavailable
	}
	prior, previous, ok := parseLifetime(old)
	if !ok || phase == 'U' && (prior != 'C' || !h.live()) || phase == 'C' && (prior != 'U' || previous != record) {
		return ErrUnavailable
	}
	raw, ok := lifetimeFrame(phase, record)
	if !ok {
		return ErrUnavailable
	}
	n, e := h.lifetime.file.WriteAt(raw[:], 0)
	if e != nil || n != len(raw) {
		return ErrUnavailable
	}
	back, e := h.readLifetime()
	if e != nil || !bytes.Equal(back[:], raw[:]) || unix.Fsync(h.lifetime.fd()) != nil || unix.Fsync(h.historyDir.fd()) != nil {
		return ErrUnavailable
	}
	after, e := h.lifetimeFacts()
	if e != nil || phase == 'U' && !h.live() {
		return ErrUnavailable
	}
	verify, e := h.readLifetime()
	if e != nil || verify != raw {
		return ErrUnavailable
	}
	h.stateFrame, h.stateRecord, h.stateFacts = raw, record, after
	return nil
}
