//go:build !openbsd || !aegvium_transport_source || !aegvium_engine_source || !no_fs_access

// SPDX-License-Identifier: BSD-3-Clause
package main

import "os"

// Operational admission is absent. A default build never initializes policy,
// reads credentials, acquires control, listens or forwards.
func main() { os.Exit(77) }
