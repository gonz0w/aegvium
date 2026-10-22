//go:build openbsd && aegvium_transport_source && aegvium_engine_source && no_fs_access

// SPDX-License-Identifier: BSD-3-Clause
package main

import (
	"os"

	"github.com/gonz0w/aegvium/internal/inspectorstartup"
)

func main() {
	if len(os.Args) != 1 || inspectorstartup.RunSource() != nil {
		os.Exit(1)
	}
}
