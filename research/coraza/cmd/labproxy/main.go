// SPDX-License-Identifier: BSD-3-Clause
// Runnable owned-guest prototype, never an installed appliance service.
package main

import (
	"bytes"
	"flag"
	"fmt"
	spike "github.com/gonz0w/aegvium/research/coraza"
	"os"
	"os/signal"
	"runtime"
	"syscall"
)

func main() {
	if runtime.GOOS != "openbsd" || os.Geteuid() == 0 || os.Getenv("AEGVIUM_LAB_PROXY") != "owned-guest" {
		fmt.Fprintln(os.Stderr, "owned nonroot OpenBSD lab only")
		os.Exit(2)
	}
	flags := flag.NewFlagSet("labproxy", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	path := flags.String("config", "", "owned route file")
	check := flags.Bool("check", false, "validate without binding")
	certFile := flags.String("tls-cert", "", "startup-only owned public certificate")
	clientIP := flags.Bool("proxy-client-ip", false, "use validated PROXY source; requires external PF sender boundary and frontend TLS")
	keyFile := flags.String("tls-key", "", "startup-only owned private key")
	if flags.Parse(os.Args[1:]) != nil || flags.NArg() != 0 || *path == "" || (*certFile == "") != (*keyFile == "") || (*clientIP && *certFile == "") {
		fmt.Fprintln(os.Stderr, "lab arguments invalid")
		os.Exit(2)
	}
	readConfig := func() (spike.LabConfig, error) {
		data, e := spike.ReadLabFile(*path, spike.LabConfigLimit)
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
	profile := config.Profile()
	profile.ProxyClientIP = *clientIP
	if *certFile != "" {
		profile.FrontendCertificate, e = spike.ReadLabCertificate(*certFile, *keyFile)
		if e == nil {
			e = spike.CheckLabFrontend(profile)
		}
		if e != nil {
			fmt.Fprintln(os.Stderr, "lab frontend TLS invalid")
			os.Exit(2)
		}
	}
	if *check {
		fmt.Println("owned lab config accepted")
		return
	}
	stopped := make(chan os.Signal, 1)
	reloaded := make(chan os.Signal, 1)
	signal.Notify(stopped, syscall.SIGTERM, syscall.SIGINT)
	signal.Notify(reloaded, syscall.SIGHUP)
	defer signal.Stop(reloaded)
	defer signal.Stop(stopped)
	f, e := spike.StartLabProxy(profile)
	if e != nil {
		fmt.Fprintln(os.Stderr, "lab startup failed")
		os.Exit(1)
	}
	if status := runLabControl(f, readConfig, stopped, reloaded, os.Stdout, os.Stderr); status != 0 {
		os.Exit(status)
	}
}
