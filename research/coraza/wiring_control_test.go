// SPDX-License-Identifier: BSD-3-Clause
package spike

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

type wiringCommand struct {
	phase     uint64
	operation string
}
type wiringAck struct {
	Schema     int           `json:"schema"`
	Generation string        `json:"generation"`
	UID        int           `json:"uid"`
	Phase      uint64        `json:"phase"`
	Operation  string        `json:"operation"`
	Ready      bool          `json:"ready"`
	Terminal   bool          `json:"terminal"`
	Cleaned    bool          `json:"cleaned"`
	Events     []wiringEvent `json:"events"`
}

func parseWiringCommand(data []byte) (wiringCommand, error) {
	if len(data) > 128 || !strings.HasSuffix(string(data), "\n") {
		return wiringCommand{}, errors.New("invalid control size/terminator")
	}
	fields := strings.Split(strings.TrimSuffix(string(data), "\n"), "\t")
	if len(fields) != 2 {
		return wiringCommand{}, errors.New("invalid control fields")
	}
	phase, err := strconv.ParseUint(fields[0], 10, 64)
	if err != nil || phase == 0 || phase > 16 || strconv.FormatUint(phase, 10) != fields[0] {
		return wiringCommand{}, errors.New("invalid phase")
	}
	if wiringOperation(fields[1]) {
		return wiringCommand{phase, fields[1]}, nil
	}
	return wiringCommand{}, errors.New("unknown operation")
}

func readWiringCommand(path string) (wiringCommand, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return wiringCommand{}, err
	}
	if !info.Mode().IsRegular() || info.Size() > 128 {
		return wiringCommand{}, errors.New("invalid control file")
	}
	file, err := os.Open(path)
	if err != nil {
		return wiringCommand{}, err
	}
	defer file.Close()
	info, err = file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return wiringCommand{}, errors.New("invalid opened control file")
	}
	data, err := io.ReadAll(io.LimitReader(file, 129))
	if err != nil {
		return wiringCommand{}, err
	}
	return parseWiringCommand(data)
}

func writeWiringAck(path string, ack wiringAck) error {
	data, err := json.Marshal(ack)
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".ack-")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name)
	_, err = file.Write(append(data, '\n'))
	closed := file.Close()
	if err != nil {
		return err
	}
	if closed != nil {
		return closed
	}
	return os.Rename(name, path)
}

// Caller supplies only owned fixture/control paths; the native entry fixes all paths.
func runWiringControls(ctx context.Context, f *wiringFixture, control, receipt string) (result error) {
	defer func() {
		if err := f.close(); err != nil && result == nil {
			result = err
		}
	}()
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	ack := wiringAck{Schema: 1, Generation: hex.EncodeToString(nonce[:]), UID: os.Geteuid(), Operation: "startup"}
	last := wiringCommand{}
	refresh := func() error {
		f.mu.Lock()
		ack.Terminal = f.terminal
		ack.Events = append([]wiringEvent(nil), f.events...)
		f.mu.Unlock()
		ack.Ready = f.receiver.Ready()
		return writeWiringAck(receipt, ack)
	}
	if err := refresh(); err != nil {
		return err
	}
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
		command, err := readWiringCommand(control)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if command != last {
			if command.phase <= last.phase {
				return errors.New("stale/changed control phase")
			}
			if command.operation == "stop" {
				f.mu.Lock()
				busy := f.active != 0
				f.mu.Unlock()
				if busy {
					return errors.New("stop while active")
				}
				if err := f.close(); err != nil {
					return err
				}
				for _, listener := range f.listeners {
					connection, err := net.DialTimeout("tcp4", listener.Addr().String(), 100*time.Millisecond)
					if err == nil {
						connection.Close()
						return errors.New("listener survived stop")
					}
				}
				ack.Phase = command.phase
				ack.Operation = "stop"
				ack.Cleaned = true
				return refresh()
			}
			if err := f.apply(command.phase, command.operation); err != nil {
				return err
			}
			last = command
			ack.Phase = command.phase
			ack.Operation = command.operation
		}
		if err := refresh(); err != nil {
			return err
		}
	}
}

func TestNativeWiringFixture(t *testing.T) {
	if runtime.GOOS != "openbsd" || os.Getenv("AEGVIUM_WIRING_FIXTURE") != "owned-guest" {
		t.Skip("requires separately owned native wiring supervisor")
	}
	if os.Geteuid() == 0 {
		t.Fatal("wiring fixture must be unprivileged")
	}
	f, err := startWiringFixture(netip.MustParseAddrPort("127.0.0.1:18120"), [3]uint16{18121, 18084, 18085})
	if err != nil {
		t.Fatal(err)
	}
	budget := 240 * time.Second
	if os.Getenv("AEGVIUM_WIRING_FAULTS") == "owned-guest" {
		budget = 360 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	if err := runWiringControls(ctx, f, "/var/aegvium-wiring/control/phase", "/var/aegvium-wiring/receipts/state.json"); err != nil {
		t.Fatal(err)
	}
}
