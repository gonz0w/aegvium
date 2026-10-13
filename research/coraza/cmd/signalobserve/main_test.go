// SPDX-License-Identifier: BSD-3-Clause
package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestArguments(t *testing.T) {
	for _, arm := range []string{"zero", "one", "two", "term", "kill"} {
		if got, ok := mode([]string{arm, "127.0.0.1"}); !ok || got != arm {
			t.Fatal(arm)
		}
	}
	for _, args := range [][]string{nil, {"term"}, {"term", "localhost"}, {"../term", "127.0.0.1"}, {"term;id", "127.0.0.1"}, {"term", "127.0.0.1", "extra"}} {
		if _, ok := mode(args); ok || observe(args) != 0 {
			t.Fatalf("accepted %q", args)
		}
	}
}

func TestChildWaitStatus(t *testing.T) {
	for _, tc := range []struct {
		name, action, kind string
		value              int
	}{
		{"zero", "exit 0", "exited", 0}, {"one", "exit 1", "exited", 1}, {"two", "exit 2", "exited", 2},
		{"term", "trap - TERM; kill -TERM $$", "signalled", int(syscall.SIGTERM)},
		{"kill", "kill -KILL $$", "signalled", int(syscall.SIGKILL)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "control")
			if err := os.WriteFile(path, []byte("#!/bin/sh\n"+tc.action+"\n"), 0700); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			got, err := runChild(ctx, path)
			if err != nil || got != (outcome{tc.kind, tc.value}) {
				t.Fatalf("%+v %v", got, err)
			}
		})
	}
	t.Run("launch-error", func(t *testing.T) {
		if got, err := runChild(context.Background(), filepath.Join(t.TempDir(), "missing")); err == nil || got.kind != "launch-error" {
			t.Fatal("launch was classified as exit")
		}
	})
	t.Run("deadline", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "silent")
		if err := os.WriteFile(path, []byte("#!/bin/sh\nwhile :; do :; done\n"), 0700); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		if got, err := runChild(ctx, path); err == nil || ctx.Err() == nil || got.kind != "deadline" {
			t.Fatal("timeout admitted")
		}
	})
}

func TestRecord(t *testing.T) {
	dir := t.TempDir()
	if err := record(dir, "two", outcome{"exited", 2}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "two.observe"))
	want := "uid\t" + strconv.Itoa(os.Geteuid()) + "\nexited\t2\n"
	if err != nil || string(data) != want {
		t.Fatalf("%q %v", data, err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatal("temporary receipt leaked")
	}
	if err := record(filepath.Join(dir, "missing"), "two", outcome{"exited", 2}); err == nil {
		t.Fatal("missing directory accepted")
	}
	if err := os.Mkdir(filepath.Join(dir, "term.observe"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := record(dir, "term", outcome{"signalled", int(syscall.SIGTERM)}); err == nil {
		t.Fatal("failed receipt replacement admitted")
	}
	entries, err = os.ReadDir(dir)
	if err != nil || len(entries) != 2 {
		t.Fatal("failed replacement leaked temporary receipt")
	}
	if propagate(outcome{"unexpected", 2}) != 0 {
		t.Fatal("unexpected result positive")
	}
}

func TestPropagationChild(t *testing.T) {
	if arg := os.Getenv("AEGVIUM_PROPAGATION_CHILD"); arg != "" {
		parts := strings.Split(arg, ":")
		value, err := strconv.Atoi(parts[1])
		if err != nil {
			os.Exit(0)
		}
		os.Exit(propagate(outcome{parts[0], value}))
	}
}

func TestPropagation(t *testing.T) {
	for _, result := range []outcome{{"exited", 0}, {"exited", 1}, {"exited", 2}, {"signalled", int(syscall.SIGTERM)}, {"signalled", int(syscall.SIGKILL)}} {
		t.Run(result.kind+strconv.Itoa(result.value), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestPropagationChild$")
			cmd.Env = append(os.Environ(), "AEGVIUM_PROPAGATION_CHILD="+result.kind+":"+strconv.Itoa(result.value))
			_ = cmd.Run()
			if ctx.Err() != nil || cmd.ProcessState == nil {
				t.Fatal("child not reaped")
			}
			status, ok := cmd.ProcessState.Sys().(syscall.WaitStatus)
			if !ok {
				t.Fatal("unsupported status")
			}
			got, err := classify(status)
			if err != nil || got != result {
				t.Fatalf("got %+v %v want %+v", got, err, result)
			}
		})
	}
}
