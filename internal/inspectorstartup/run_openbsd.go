//go:build openbsd && aegvium_transport_source && aegvium_engine_source && no_fs_access

// SPDX-License-Identifier: BSD-3-Clause
// Package inspectorstartup composes one real inspector startup. This source
// entry prepares policy/pairing and retirement only: no data-ready/forward path.
package inspectorstartup

import (
	"errors"
	"io"
	"sync/atomic"

	"github.com/gonz0w/aegvium/internal/bodyowner"
	"github.com/gonz0w/aegvium/internal/requestctx"
)

var errStartup = errors.New("inspector startup unavailable")
var process struct {
	attempted atomic.Bool
	pair      *requestctx.InspectorSource
	engine    *bodyowner.InspectorEngineSource
	control   io.ReadWriteCloser
}

// RunSource has no material, descriptor, process or provider arguments. It is
// reachable only in the explicit source build, never an installed/default run.
func RunSource() (err error) {
	if !process.attempted.CompareAndSwap(false, true) {
		return errStartup
	}
	defer func() {
		if recover() != nil {
			err = errStartup
		}
		if err != nil && process.engine != nil {
			process.engine.StopSource()
		}
	}()
	process.pair, err = requestctx.PrepareInspectorSource()
	if err != nil {
		return errStartup
	}
	process.engine, err = bodyowner.PrepareInspectorEngineSource(process.pair.Generation(), process.pair.PolicyPinSource())
	if err != nil {
		return errStartup
	}
	if process.pair.ConfirmPreparedSource() != nil {
		return errStartup
	}
	process.control, err = process.pair.ClaimControlSource()
	if err != nil {
		return errStartup
	}
	if process.engine.RetireControlSource(process.control) != nil {
		return errStartup
	}
	return nil
}
