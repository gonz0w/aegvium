// SPDX-License-Identifier: BSD-3-Clause
package main

import (
	"context"
	"errors"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestCheckerExit(t *testing.T) {
	for _, tc := range []struct {
		name string
		code int
		want int
	}{
		{"healthy", 1, 1}, {"down", 0, 0}, {"unexpected-positive", 2, 0}, {"unexpected-negative", -1, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := checkerExit(func() int { return tc.code }); got != tc.want {
				t.Fatalf("exit=%d want=%d", got, tc.want)
			}
		})
	}
	t.Run("panic", func(t *testing.T) {
		if checkerExit(func() int { panic("fixture failure") }) != 0 {
			t.Fatal("panic was healthy")
		}
	})
}
func TestCheckerInvalidProcess(t *testing.T) {
	// Only invalid arguments: these children must never connect to a host service.
	binary := filepath.Join(t.TempDir(), "readycheck")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	build := exec.CommandContext(ctx, filepath.Join(runtime.GOROOT(), "bin", "go"), "build", "-o", binary, ".")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, output)
	}
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"missing", nil}, {"hostname", []string{"localhost"}}, {"extra", []string{"127.0.0.1", "extra"}}, {"other-address", []string{"127.0.0.2"}}, {"metacharacters", []string{"127.0.0.1;id"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			output, err := exec.CommandContext(ctx, binary, tc.args...).CombinedOutput()
			if ctx.Err() != nil || err != nil || len(output) != 0 {
				var exit *exec.ExitError
				if errors.As(err, &exit) {
					t.Fatalf("unexpected exit %d", exit.ExitCode())
				}
				t.Fatalf("result: %v output=%q", err, output)
			}
		})
	}
}
