//go:build !openbsd || !aegvium_service_source

// SPDX-License-Identifier: BSD-3-Clause
package main

import "os"

func main() { os.Exit(77) }
