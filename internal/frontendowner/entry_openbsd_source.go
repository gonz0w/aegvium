//go:build openbsd && aegvium_frontend_source

// SPDX-License-Identifier: BSD-3-Clause
package frontendowner

import (
	"context"
	"os/signal"
	"syscall"
)

// No argument, environment, receipt, FD or test provider can enable this gate.
// Exact package/loader/material/resource/native acceptance remains unavailable.
const nativeFrontendQualified = false

func runQualifiedSource() error {
	if !nativeFrontendQualified {
		return ErrUnavailable
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	return runPreparedSource(ctx)
}
