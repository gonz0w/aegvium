//go:build openbsd && aegvium_commission_source

// SPDX-License-Identifier: BSD-3-Clause
package main

import (
	"os"

	"github.com/gonz0w/aegvium/internal/commissionplace"
)

// The qualification gate remains false before all target/native effects. No
// argument, receipt or environment override is an operational enable switch.
func main() {
	if len(os.Args) != 1 || commissionplace.RunProduction() != nil {
		os.Exit(77)
	}
}
