// SPDX-License-Identifier: BSD-3-Clause
// Fixed-purpose research instrumentation, never a readiness checker.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"
)

const fixture = "/var/aegvium-signal"

type outcome struct {
	kind  string
	value int
}

func mode(args []string) (string, bool) {
	if len(args) != 2 || args[1] != "127.0.0.1" {
		return "", false
	}
	switch args[0] {
	case "zero", "one", "two", "term", "kill":
		return args[0], true
	}
	return "", false
}

func classify(status syscall.WaitStatus) (outcome, error) {
	switch {
	case status.Exited():
		return outcome{"exited", status.ExitStatus()}, nil
	case status.Signaled():
		return outcome{"signalled", int(status.Signal())}, nil
	default:
		return outcome{}, errors.New("unexpected wait status")
	}
}

func runChild(ctx context.Context, path string) (outcome, error) {
	cmd := exec.CommandContext(ctx, path, "127.0.0.1")
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	err := cmd.Run() // Always reaps the direct child; no shell command interpolation.
	if ctx.Err() != nil {
		return outcome{"deadline", 0}, errors.New("child deadline")
	}
	var exit *exec.ExitError
	if err != nil && !errors.As(err, &exit) {
		return outcome{"launch-error", 0}, errors.New("child launch error")
	}
	if cmd.ProcessState == nil {
		return outcome{"status-error", 0}, errors.New("missing process state")
	}
	status, ok := cmd.ProcessState.Sys().(syscall.WaitStatus)
	if !ok {
		return outcome{"status-error", 0}, errors.New("unsupported process status")
	}
	result, err := classify(status)
	if err != nil {
		return outcome{"status-error", 0}, err
	}
	return result, nil
}

func record(dir, arm string, result outcome) error {
	file, err := os.CreateTemp(dir, ".observe-")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name)
	_, writeErr := fmt.Fprintf(file, "uid\t%d\n%s\t%d\n", os.Geteuid(), result.kind, result.value)
	closeErr := file.Close()
	if writeErr != nil {
		return writeErr
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(name, filepath.Join(dir, arm+".observe"))
}

func propagate(result outcome) int {
	if result.kind == "exited" && result.value >= 0 && result.value <= 255 {
		return result.value
	}
	if result.kind == "signalled" && (result.value == int(syscall.SIGTERM) || result.value == int(syscall.SIGKILL)) {
		sig := syscall.Signal(result.value)
		signal.Reset(sig) // Instrumentation changes disposition; never claim a plain-shell status.
		if syscall.Kill(os.Getpid(), sig) == nil {
			time.Sleep(100 * time.Millisecond)
		}
	}
	return 0 // Unsupported/failed propagation is never intentionally a positive exit.
}

func observe(args []string) int {
	arm, valid := mode(args)
	if !valid || runtime.GOOS != "openbsd" || os.Geteuid() == 0 {
		return 0
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	result, err := runChild(ctx, fixture+"/"+arm+".sh")
	if err != nil {
		_ = record(fixture+"/evidence", arm, result)
		return 0
	}
	if record(fixture+"/evidence", arm, result) != nil {
		return 0
	}
	code := propagate(result)
	if result.kind == "signalled" {
		// Reaching here means propagation did not terminate this observer.
		_ = record(fixture+"/evidence", arm, outcome{"propagation-error", 0})
		return 0
	}
	return code
}

func main() { os.Exit(observe(os.Args[1:])) }
