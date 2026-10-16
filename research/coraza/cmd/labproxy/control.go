// SPDX-License-Identifier: BSD-3-Clause
package main

import (
	"errors"
	"fmt"
	spike "github.com/gonz0w/aegvium/research/coraza"
	"io"
	"os"
)

type labRuntime interface {
	Failed() <-chan struct{}
	Reload([]spike.LabRoute) error
	Close() error
}

func labFailure(failed <-chan struct{}) bool {
	select {
	case <-failed:
		return true
	default:
		return false
	}
}

func runLabControl(f labRuntime, readConfig func() (spike.LabConfig, error), stopped, reloaded <-chan os.Signal, output, diagnostic io.Writer) int {
	failed := f.Failed()
	finish := func() int {
		err := f.Close()
		if err != nil {
			fmt.Fprintln(diagnostic, "lab cleanup failed")
		}
		if labFailure(failed) {
			fmt.Fprintln(diagnostic, "lab server stopped unexpectedly")
			return 1
		}
		if err != nil {
			return 1
		}
		return 0
	}
	if labFailure(failed) {
		return finish()
	}
	select {
	case <-stopped:
		return finish()
	default:
	}
	fmt.Fprintln(output, "owned lab companion ready")
	for {
		if labFailure(failed) {
			return finish()
		}
		// A pending stop takes priority over a queued reload.
		select {
		case <-stopped:
			return finish()
		default:
		}
		select {
		case <-failed:
			return finish()
		case <-stopped:
			return finish()
		case <-reloaded:
		}
		if labFailure(failed) {
			return finish()
		}
		select {
		case <-stopped:
			return finish()
		default:
		}
		replacement, err := readConfig()
		if labFailure(failed) {
			return finish()
		}
		if err == nil {
			err = f.Reload(replacement.Routes)
		}
		if errors.Is(err, spike.ErrLabReloadCleanup) {
			fmt.Fprintln(diagnostic, "lab reload cleanup failed")
			_ = finish()
			return 1
		}
		if labFailure(failed) {
			return finish()
		}
		if err != nil {
			fmt.Fprintln(output, "owned lab reload rejected")
		} else {
			fmt.Fprintln(output, "owned lab reload accepted")
		}
	}
}
