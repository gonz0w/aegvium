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
	if len(os.Args) == 2 && os.Args[1] == "prepare-successor" {
		if frontendowner.PrepareSuccessorSource() != nil {
			os.Exit(77)
		}
		return
	}
	if len(os.Args) != 1 || frontendowner.RunSource() != nil {
		os.Exit(77)
	}
	os.Exit(77)
}
