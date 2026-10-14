// SPDX-License-Identifier: BSD-3-Clause
// Runnable owned-guest prototype, never an installed appliance service.
package main

import (
	"fmt"
	spike "github.com/gonz0w/aegvium/research/coraza"
	"net/netip"
	"os"
	"os/signal"
	"runtime"
	"syscall"
)

func main() {
	if runtime.GOOS != "openbsd" || os.Geteuid() == 0 || os.Getenv("AEGVIUM_LAB_PROXY") != "owned-guest" || len(os.Args) != 1 {
		fmt.Fprintln(os.Stderr, "owned nonroot OpenBSD lab only")
		os.Exit(2)
	}
	stopped := make(chan os.Signal, 1)
	signal.Notify(stopped, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(stopped)
	f, e := spike.StartLabProxy(spike.LabProfile{DataAddress: "127.0.0.1:18084", HealthAddress: "127.0.0.1:18085", BackendAddress: "127.0.0.1:18086", Ingress: netip.MustParseAddrPort("127.0.0.1:18120")})
	if e != nil {
		fmt.Fprintln(os.Stderr, "lab startup failed")
		os.Exit(1)
	}
	fmt.Println("owned lab companion ready")
	<-stopped
	if f.Close() != nil {
		fmt.Fprintln(os.Stderr, "lab cleanup failed")
		os.Exit(1)
	}
}
