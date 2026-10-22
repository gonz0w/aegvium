//go:build openbsd && aegvium_transport_source && aegvium_engine_source && no_fs_access

// SPDX-License-Identifier: BSD-3-Clause
// Package inspectorstartup composes one real inspector startup. This source
// entry composes policy, pairing, DATA and retirement ownership. The immutable
// false qualification gate refuses before any credential/engine/network effect.
package inspectorstartup

import (
	"context"
	"errors"
	"io"
	"sync/atomic"
	"time"

	"github.com/gonz0w/aegvium/internal/bodyowner"
	"github.com/gonz0w/aegvium/internal/requestctx"
)

var errStartup = errors.New("inspector startup unavailable")
var process struct {
	attempted atomic.Bool
	pair      *requestctx.InspectorSource
	engine    *bodyowner.InspectorEngineSource
	control   io.ReadWriteCloser
	network   *requestctx.SourceListeners
}

// RunSource has no material, descriptor, process or provider arguments. It is
// reachable only in the explicit source build, never an installed/default run.
func RunSource() (err error) {
	if !requestctx.SourceNetworkQualified() {
		return errStartup
	}
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
	process.network, err = process.pair.PrepareNetworkSource()
	if err != nil {
		return errStartup
	}
	process.control, err = process.pair.ClaimControlSource()
	if err != nil {
		return errStartup
	}
	dataDone, controlDone, retireDone := make(chan error, 1), make(chan error, 1), make(chan error, 1)
	go func() { dataDone <- process.engine.ServeDataSource(process.network) }()
	go func() { controlDone <- process.network.ServeControlSource() }()
	go func() { retireDone <- process.engine.RetireControlSource(process.control) }()
	var dataJoined, controlJoined bool
	select {
	case err = <-retireDone:
	case <-dataDone:
		dataJoined = true
		err = errStartup
	case <-controlDone:
		controlJoined = true
		err = errStartup
	}
	process.engine.StopSource()
	if process.network.StopSource() != nil {
		return errStartup
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if !dataJoined {
		select {
		case <-dataDone:
		case <-ctx.Done():
			return errStartup
		}
	}
	if !controlJoined {
		select {
		case <-controlDone:
		case <-ctx.Done():
			return errStartup
		}
	}
	if process.engine.WaitDataSource(ctx) != nil {
		return errStartup
	}
	return err
}
