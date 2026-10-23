//go:build !openbsd || !aegvium_commission_source

// SPDX-License-Identifier: BSD-3-Clause
package main

import "os"

// No installed placement entry until the exact input/native profile qualifies.
func main() { os.Exit(77) }
