//go:build openbsd && (amd64 || arm64) && aegvium_service_source

// SPDX-License-Identifier: BSD-3-Clause
package main

import (
	"os"

	"github.com/gonz0w/aegvium/internal/localcontrol"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "mode" {
		mode, err := localcontrol.ModeSource()
		if err != nil {
			os.Exit(77)
		}
		if n, e := os.Stdout.WriteString(mode); e != nil || n != len(mode) {
			os.Exit(1)
		}
		return
	}
	if len(os.Args) != 3 {
		os.Exit(77)
	}
	reply, err := localcontrol.QuerySource(os.Args[1], os.Args[2])
	if err != nil {
		os.Exit(77)
	}
	if n, err := os.Stdout.WriteString(reply); err != nil || n != len(reply) {
		os.Exit(1)
	}
	if os.Args[2] == "stop" {
		os.Exit(2)
	} // accepted request, never reclaimed
}
