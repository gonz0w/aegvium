//go:build openbsd && aegvium_frontend_source

// SPDX-License-Identifier: BSD-3-Clause
package main

import (
	"github.com/gonz0w/aegvium/internal/frontendowner"
	"os"
)

// The immutable source entry still refuses before all privileged/file/TLS/child
// operations. Source composition is not admission and has no enable argument.
func main() {
	if frontendowner.RunSource() != nil {
		os.Exit(77)
	}
	os.Exit(77)
}
