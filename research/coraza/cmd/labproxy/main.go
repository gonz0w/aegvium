// SPDX-License-Identifier: BSD-3-Clause
// Runnable owned-guest prototype, never an installed appliance service.
package main

import (
	"bytes"
	"errors"
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
	readConfig := func() (spike.LabConfig, error) {
		data, e := spike.ReadLabFile(os.Args[2], spike.LabConfigLimit)
		if e != nil {
			return spike.LabConfig{}, e
		}
		return spike.ReadLabConfig(bytes.NewReader(data))
	}
	config, e := readConfig()
	if e != nil {
		fmt.Fprintln(os.Stderr, "lab config invalid")
		os.Exit(2)
	}
	if len(os.Args) == 4 {
		fmt.Println("owned lab config accepted")
		return
	}
	stopped := make(chan os.Signal, 1)
	reloaded := make(chan os.Signal, 1)
	signal.Notify(stopped, syscall.SIGTERM, syscall.SIGINT)
	signal.Notify(reloaded, syscall.SIGHUP)
	defer signal.Stop(reloaded)
	defer signal.Stop(stopped)
	f, e := spike.StartLabProxy(config.Profile())
	if e != nil {
		fmt.Fprintln(os.Stderr, "lab startup failed")
		os.Exit(1)
	}
	fmt.Println("owned lab companion ready")
running:
	for {
		select {
		case <-stopped:
			break running
		default:
		}
		select {
		case <-stopped:
			break running
		case <-reloaded:
		}

		replacement, e := readConfig()
		if e == nil {
			e = f.Reload(replacement.Routes)
		}
		if errors.Is(e, spike.ErrLabReloadCleanup) {
			fmt.Fprintln(os.Stderr, "lab reload cleanup failed")
			_ = f.Close()
			os.Exit(1)
		}
		if e != nil {
			fmt.Println("owned lab reload rejected")
		} else {
			fmt.Println("owned lab reload accepted")
		}
	}
	if f.Close() != nil {
		fmt.Fprintln(os.Stderr, "lab cleanup failed")
		os.Exit(1)
	}
}
