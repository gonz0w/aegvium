// SPDX-License-Identifier: BSD-3-Clause
package spike

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"testing"
	"time"
)

func TestReadyCheckerTCP(t *testing.T) {
	if runtime.GOOS != "openbsd" || os.Getenv("AEGVIUM_NATIVE_REPEAT") != "1" {
		t.Skip("requires owned native OpenBSD repeat")
	}
	for _, name := range []string{"transitions", "refused", "silent", "malformed", "invalid-argument", "missing-executable"} {
		t.Run(name, func(t *testing.T) {
			const address = "127.0.0.1:18085"
			const helper = "/var/aegvium-lab-readycheck"
			// Reject a contaminated fixed-port fixture before running any probe.
			c, err := net.DialTimeout("tcp4", address, time.Second)
			if err == nil {
				_ = c.Close()
				t.Fatal("fixture health port already occupied")
			}
			run := func(path string, args []string, want int) {
				t.Helper()
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				command := exec.CommandContext(ctx, path, args...)
				command.Env = []string{"PATH=/usr/bin:/bin"}
				output, err := command.CombinedOutput()
				code := 0
				if err != nil {
					var exit *exec.ExitError
					if !errors.As(err, &exit) {
						t.Fatalf("process launch: %v", err)
					}
					code = exit.ExitCode()
				}
				if ctx.Err() != nil || code != want || len(output) != 0 {
					t.Fatalf("checker exit=%d want=%d deadline=%v output=%q", code, want, ctx.Err(), output)
				}
				t.Logf("checker-process exit=%d output-bytes=0", code)
			}
			if name == "missing-executable" {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				err := exec.CommandContext(ctx, "/var/aegvium-lab-missing-readycheck", "127.0.0.1").Run()
				if !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("missing helper: %v", err)
				}
				t.Log("checker-missing launch-error=verified; not a process exit")
				return
			}
			if name == "refused" {
				run(helper, []string{"127.0.0.1"}, 0)
				return
			}
			if name == "invalid-argument" {
				run(helper, []string{"localhost"}, 0)
				return
			}
			listener, err := net.Listen("tcp4", address)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = listener.Close() })
			if name == "transitions" {
				_, receiver, engine := proxyListenerFixture(t)
				engine.Store(false)
				server := proxyReadyServer(receiver)
				done := make(chan error, 1)
				go func() { done <- server.Serve(listener) }()
				t.Cleanup(func() { _ = server.Close() })
				run(helper, []string{"127.0.0.1"}, 0)
				engine.Store(true)
				run(helper, []string{"127.0.0.1"}, 1)
				engine.Store(false)
				run(helper, []string{"127.0.0.1"}, 0)
				engine.Store(true)
				run(helper, []string{"127.0.0.1"}, 1)
				proxyCloseListener(t, receiver)
				run(helper, []string{"127.0.0.1"}, 0)
				if err = server.Close(); err != nil {
					t.Fatal(err)
				}
				select {
				case err = <-done:
					if !errors.Is(err, http.ErrServerClosed) {
						t.Fatal(err)
					}
				case <-time.After(3 * time.Second):
					t.Fatal("health server did not join")
				}
			} else {
				done := make(chan error, 1)
				release := make(chan struct{})
				go func() {
					c, err := listener.Accept()
					if err != nil {
						done <- err
						return
					}
					defer c.Close()
					_ = c.SetDeadline(time.Now().Add(3 * time.Second))
					request, err := httpProbeRequest(bufio.NewReader(c))
					if err != nil || request != "HEAD /ready HTTP/1.0\r\n\r\n" {
						done <- errors.New("unexpected checker request")
						return
					}
					if name == "malformed" {
						_, err = io.WriteString(c, "garbage\r\n\r\n")
					} else {
						<-release
					}
					done <- err
				}()
				t.Cleanup(func() {
					select {
					case <-release:
					default:
						close(release)
					}
				})
				run(helper, []string{"127.0.0.1"}, 0)
				close(release)
				select {
				case err = <-done:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(3 * time.Second):
					t.Fatal("response peer did not join")
				}
				_ = listener.Close()
			}
			c, err = net.DialTimeout("tcp4", address, time.Second)
			if err == nil {
				_ = c.Close()
				t.Fatal("checker fixture listener survived")
			}
			t.Log("checker-health absence=verified peer-or-server-joined=true")
		})
	}
}
