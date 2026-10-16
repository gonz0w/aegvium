// SPDX-License-Identifier: BSD-3-Clause
package main

import (
	"bytes"
	"errors"
	spike "github.com/gonz0w/aegvium/research/coraza"
	"os"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

type fakeLabRuntime struct {
	failed          chan struct{}
	onReload        func([]spike.LabRoute) error
	onClose         func() error
	reloads, closes int
}

func (f *fakeLabRuntime) Failed() <-chan struct{} { return f.failed }
func (f *fakeLabRuntime) Reload(routes []spike.LabRoute) error {
	f.reloads++
	if f.onReload != nil {
		return f.onReload(routes)
	}
	return nil
}
func (f *fakeLabRuntime) Close() error {
	f.closes++
	if f.onClose != nil {
		return f.onClose()
	}
	return nil
}

type labReadyWriter struct {
	bytes.Buffer
	ready chan struct{}
	once  sync.Once
}

func (w *labReadyWriter) Write(data []byte) (int, error) {
	n, err := w.Buffer.Write(data)
	if strings.Contains(string(data), "owned lab companion ready") {
		w.once.Do(func() { close(w.ready) })
	}
	return n, err
}

func TestLabControlServerFailure(t *testing.T) {
	for _, beforeReady := range []bool{true, false} {
		f := &fakeLabRuntime{failed: make(chan struct{})}
		stopped := make(chan os.Signal, 1)
		reloaded := make(chan os.Signal, 1)
		output := &labReadyWriter{ready: make(chan struct{})}
		var diagnostic bytes.Buffer
		if beforeReady {
			close(f.failed)
		}
		done := make(chan int, 1)
		go func() { done <- runLabControl(f, nil, stopped, reloaded, output, &diagnostic) }()
		if !beforeReady {
			select {
			case <-output.ready:
			case <-time.After(time.Second):
				stopped <- syscall.SIGTERM
				t.Fatal("control did not reach wait state")
			}
			close(f.failed)
		}
		select {
		case status := <-done:
			if status != 1 || f.closes != 1 || f.reloads != 0 || diagnostic.String() != "lab server stopped unexpectedly\n" {
				t.Fatal("server failure did not stop owner with generic failure")
			}
			if beforeReady && output.Len() != 0 {
				t.Fatal("already failed runtime announced ready")
			}
		case <-time.After(time.Second):
			stopped <- syscall.SIGTERM
			t.Fatal("failure did not wake signal wait")
		}
	}
}

func TestLabControlStopPriority(t *testing.T) {
	f := &fakeLabRuntime{failed: make(chan struct{})}
	stop, reload := make(chan os.Signal, 1), make(chan os.Signal, 1)
	stop <- syscall.SIGTERM
	reload <- syscall.SIGHUP
	var output, diagnostic bytes.Buffer
	read := func() (spike.LabConfig, error) {
		t.Fatal("stop permitted queued reload")
		return spike.LabConfig{}, nil
	}
	if runLabControl(f, read, stop, reload, &output, &diagnostic) != 0 || f.closes != 1 || f.reloads != 0 || output.Len() != 0 || diagnostic.Len() != 0 {
		t.Fatal("requested stop changed exit or reload behavior")
	}
}

func TestLabControlReload(t *testing.T) {
	for _, mode := range []string{"accepted", "config-error", "reload-error", "retirement-error"} {
		t.Run(mode, func(t *testing.T) {
			f := &fakeLabRuntime{failed: make(chan struct{})}
			stop, reload := make(chan os.Signal, 1), make(chan os.Signal, 1)
			reload <- syscall.SIGHUP
			config := spike.LabConfig{Version: 1, Routes: []spike.LabRoute{{Host: "app.test", Backend: "http://127.0.0.1:18086"}}}
			reads := 0
			read := func() (spike.LabConfig, error) {
				reads++
				if mode == "config-error" {
					stop <- syscall.SIGTERM
					return spike.LabConfig{}, errors.New("private marker")
				}
				return config, nil
			}
			f.onReload = func(routes []spike.LabRoute) error {
				if !reflect.DeepEqual(routes, config.Routes) {
					t.Fatal("route callback changed")
				}
				stop <- syscall.SIGTERM
				if mode == "reload-error" {
					return errors.New("private marker")
				}
				if mode == "retirement-error" {
					return errors.Join(spike.ErrLabReloadCleanup, errors.New("private marker"))
				}
				return nil
			}
			var output, diagnostic bytes.Buffer
			status := runLabControl(f, read, stop, reload, &output, &diagnostic)
			wantStatus, wantReloads := 0, 1
			if mode == "retirement-error" {
				wantStatus = 1
			}
			if mode == "config-error" {
				wantReloads = 0
			}
			if status != wantStatus || reads != 1 || f.reloads != wantReloads || f.closes != 1 || strings.Contains(output.String()+diagnostic.String(), "private marker") {
				t.Fatal("reload lifecycle or generic output changed")
			}
			want := "owned lab companion ready\n"
			if mode == "accepted" {
				want += "owned lab reload accepted\n"
			} else if mode != "retirement-error" {
				want += "owned lab reload rejected\n"
			}
			if output.String() != want || (mode == "retirement-error") != (diagnostic.String() == "lab reload cleanup failed\n") {
				t.Fatal("reload acknowledgment changed")
			}
		})
	}
}

func TestLabControlFailureDuringReload(t *testing.T) {
	for _, phase := range []string{"read", "reload"} {
		t.Run(phase, func(t *testing.T) {
			f := &fakeLabRuntime{failed: make(chan struct{})}
			stop, reload := make(chan os.Signal, 1), make(chan os.Signal, 1)
			reload <- syscall.SIGHUP
			read := func() (spike.LabConfig, error) {
				if phase == "read" {
					close(f.failed)
				}
				return spike.LabConfig{Version: 1}, nil
			}
			f.onReload = func([]spike.LabRoute) error { close(f.failed); return nil }
			var output, diagnostic bytes.Buffer
			if runLabControl(f, read, stop, reload, &output, &diagnostic) != 1 || f.closes != 1 || output.String() != "owned lab companion ready\n" || diagnostic.String() != "lab server stopped unexpectedly\n" {
				t.Fatal("failure during reload did not stop owner")
			}
			if phase == "read" && f.reloads != 0 {
				t.Fatal("failed runtime received prepared replacement")
			}
		})
	}
}

func TestLabControlCleanupError(t *testing.T) {
	f := &fakeLabRuntime{failed: make(chan struct{}), onClose: func() error { return errors.New("private marker") }}
	stop := make(chan os.Signal, 1)
	stop <- syscall.SIGTERM
	var output, diagnostic bytes.Buffer
	if runLabControl(f, nil, stop, nil, &output, &diagnostic) != 1 || f.closes != 1 || diagnostic.String() != "lab cleanup failed\n" || output.Len() != 0 {
		t.Fatal("cleanup failure was hidden or exposed raw error")
	}
}

func TestLabControlFailureDuringClose(t *testing.T) {
	f := &fakeLabRuntime{failed: make(chan struct{})}
	f.onClose = func() error { close(f.failed); return nil }
	stop := make(chan os.Signal, 1)
	stop <- syscall.SIGTERM
	var output, diagnostic bytes.Buffer
	if runLabControl(f, nil, stop, nil, &output, &diagnostic) != 1 || f.closes != 1 || diagnostic.String() != "lab server stopped unexpectedly\n" {
		t.Fatal("requested stop hid failure recorded before completion")
	}
}
