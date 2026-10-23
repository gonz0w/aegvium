//go:build !openbsd && aegvium_frontend_source

// SPDX-License-Identifier: BSD-3-Clause
package frontendowner

func runQualifiedSource() error { return ErrUnavailable }
