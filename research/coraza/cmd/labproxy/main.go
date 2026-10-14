// SPDX-License-Identifier: BSD-3-Clause
// Runnable owned-guest prototype, never an installed appliance service.
package main

import (
	"bytes"
	"fmt"
	spike "github.com/gonz0w/aegvium/research/coraza"
	"os"
	"os/signal"
	"runtime"
	"syscall"
)

func main() {
	if runtime.GOOS != "openbsd" || os.Geteuid() == 0 || os.Getenv("AEGVIUM_LAB_PROXY") != "owned-guest" || (len(os.Args) != 3 && len(os.Args) != 4) {
		fmt.Fprintln(os.Stderr, "owned nonroot OpenBSD lab only")
		os.Exit(2)
	}
	if os.Args[1] != "-config" || (len(os.Args) == 4 && os.Args[3] != "-check") {
		fmt.Fprintln(os.Stderr, "lab arguments invalid")
		os.Exit(2)
	}
	data, e := spike.ReadLabFile(os.Args[2], spike.LabConfigLimit)
	if e != nil {
		fmt.Fprintln(os.Stderr, "lab config invalid")
		os.Exit(2)
	}
	config, e := spike.ReadLabConfig(bytes.NewReader(data))
	if e != nil {
		fmt.Fprintln(os.Stderr, "lab config invalid")
		os.Exit(2)
	}
	if len(os.Args) == 4 {
		fmt.Println("owned lab config accepted")
		return
	}
	stopped := make(chan os.Signal, 1)
	signal.Notify(stopped, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(stopped)
	f, e := spike.StartLabProxy(config.Profile())
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
