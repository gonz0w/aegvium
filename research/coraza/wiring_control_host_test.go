// SPDX-License-Identifier: BSD-3-Clause
package spike

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWiringCommands(t *testing.T) {
	for _, data := range []string{"1\tdown\n", "2\tready\n", "3\tclose\n", "4\tstop\n"} {
		if _, err := parseWiringCommand([]byte(data)); err != nil {
			t.Fatal(err)
		}
	}
	for _, data := range []string{"", "1\tready", "01\tready\n", "0\tdown\n", "17\tstop\n", "1\tready\n2\tdown\n", "1\tready\textra\n", "1\t../ready\n", "1\tready;id\n", string(make([]byte, 129))} {
		if _, err := parseWiringCommand([]byte(data)); err == nil {
			t.Fatalf("accepted %q", data)
		}
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "phase")
	if err := os.WriteFile(target, []byte("1\tready\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readWiringCommand(link); err == nil {
		t.Fatal("symlink control accepted")
	}
	if _, err := readWiringCommand(dir); err == nil {
		t.Fatal("directory control accepted")
	}
}

func TestWiringControlLoop(t *testing.T) {
	for _, scenario := range []string{"transitions-stop", "changed-phase", "malformed", "deadline", "write-failure"} {
		t.Run(scenario, func(t *testing.T) {
			f, err := startWiringFixture(netip.MustParseAddrPort("127.0.0.1:18120"), [3]uint16{})
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			control := filepath.Join(dir, "phase")
			receipt := filepath.Join(dir, "state.json")
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if scenario == "deadline" {
				cancel()
			}
			if scenario == "write-failure" {
				receipt = filepath.Join(dir, "missing", "state.json")
			}
			done := make(chan error, 1)
			go func() { done <- runWiringControls(ctx, f, control, receipt) }()
			defer func() {
				cancel()
				if err := f.close(); err != nil {
					t.Error(err)
				}
			}()
			read := func(phase uint64) wiringAck {
				t.Helper()
				until := time.Now().Add(2 * time.Second)
				for time.Now().Before(until) {
					var ack wiringAck
					b, err := os.ReadFile(receipt)
					if err == nil && json.Unmarshal(b, &ack) == nil && ack.Phase == phase {
						return ack
					}
					time.Sleep(10 * time.Millisecond)
				}
				t.Fatal("acknowledgement timeout")
				return wiringAck{}
			}
			publish := func(data string) {
				t.Helper()
				tmp := filepath.Join(dir, "phase.tmp")
				if err := os.WriteFile(tmp, []byte(data), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(tmp, control); err != nil {
					t.Fatal(err)
				}
			}
			if scenario != "deadline" && scenario != "write-failure" {
				start := read(0)
				if start.Schema != 1 || len(start.Generation) != 32 || start.Ready || start.Cleaned {
					t.Fatalf("%+v", start)
				}
				if scenario == "malformed" {
					publish("1\tunknown\n")
				} else {
					publish("1\tready\n")
					ready := read(1)
					if !ready.Ready || ready.Generation != start.Generation {
						t.Fatalf("%+v", ready)
					}
					if scenario == "changed-phase" {
						publish("1\tdown\n")
					} else {
						publish("2\tdown\n")
						if read(2).Ready {
							t.Fatal("down ready")
						}
						publish("3\tready\n")
						if !read(3).Ready {
							t.Fatal("recovery down")
						}
						publish("4\tclose\n")
						closed := read(4)
						if closed.Ready || !closed.Terminal || closed.Cleaned {
							t.Fatalf("%+v", closed)
						}
						publish("5\tstop\n")
						stopped := read(5)
						if !stopped.Cleaned || stopped.Ready || stopped.Generation != start.Generation {
							t.Fatalf("%+v", stopped)
						}
					}
				}
			}
			select {
			case err := <-done:
				if (err == nil) != (scenario == "transitions-stop") {
					t.Fatalf("unexpected result %v", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("control loop did not join")
			}
			if scenario != "transitions-stop" {
				b, _ := os.ReadFile(receipt)
				var ack wiringAck
				_ = json.Unmarshal(b, &ack)
				if ack.Cleaned {
					t.Fatal("failure acknowledged successful stop")
				}
			}
		})
	}
}
