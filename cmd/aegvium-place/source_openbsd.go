//go:build openbsd && aegvium_commission_source

// SPDX-License-Identifier: BSD-3-Clause
package main

import (
	"github.com/gonz0w/aegvium/internal/commissionplace"
	"os"
)

func main() {
	if len(os.Args) != 1 || commissionplace.Run() != nil {
		os.Exit(1)
	}
}
