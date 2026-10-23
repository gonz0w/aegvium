// SPDX-License-Identifier: BSD-3-Clause
package bodyowner

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Independent pre-code review literals; neither production encoder supplies the
// expected bytes. The ACK changes only opcode, not generation/epoch/reserved.
const controlStopHex = "41474354524c310a0100000000000000303030303030303030303030303030303030303030303030303030303030303000000000000000010000000000000000"
const controlAckHex = "41474354524c310a0200000000000000303030303030303030303030303030303030303030303030303030303030303000000000000000010000000000000000"

func controlBytes(t *testing.T, value string) []byte {
	t.Helper()
	b, err := hex.DecodeString(value)
	if err != nil || len(b) != 64 {
		t.Fatal("invalid independent literal")
	}
	return b
}

type controlEndpoint struct {
	input                 *bytes.Reader
	read                  func([]byte) (int, error)
	write                 func([]byte) (int, error)
	close                 func() error
	reads, writes, closes atomic.Int32
	mu                    sync.Mutex
	output                []byte
}

func controlStream(t *testing.T) *controlEndpoint {
	return &controlEndpoint{input: bytes.NewReader(controlBytes(t, controlStopHex))}
}
func (s *controlEndpoint) Read(b []byte) (int, error) {
	s.reads.Add(1)
	if s.read != nil {
		return s.read(b)
	}
	return s.input.Read(b)
}
func (s *controlEndpoint) Write(b []byte) (int, error) {
	s.writes.Add(1)
	if s.write != nil {
		return s.write(b)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.output = append(s.output, b...)
	return len(b), nil
}
func (s *controlEndpoint) Close() error {
	s.closes.Add(1)
	if s.close != nil {
		return s.close()
	}
	return nil
}
func (s *controlEndpoint) bytes() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.output...)
}
func controlOwner(t *testing.T) (*Owner, *Generation) {
	t.Helper()
	o := New()
	g, err := o.NewGeneration(engineTestGeneration)
	if err != nil {
		t.Fatal(err)
	}
	return o, g
}
func controlStopped(t *testing.T, o *Owner, g *Generation) {
	t.Helper()
	in, err := o.ReserveInbound()
	if in != nil {
		_ = in.Close()
	}
	if err != ErrStopped {
		t.Fatal("admission did not stop", err)
	}
	o.state.mu.Lock()
	retired := g.state.retired
	o.state.mu.Unlock()
	if !retired {
		t.Fatal("generation not retired")
	}
}
func controlHeld(t *testing.T, o *Owner, want bool) {
	t.Helper()
	o.state.mu.Lock()
	held := o.state.control != nil
	o.state.mu.Unlock()
	if held != want {
		t.Fatalf("endpoint held=%v want%v", held, want)
	}
}

func TestControlGoldenRetiresBeforeAckAndDoesNotReadTrailingFrame(t *testing.T) {
	o, g := controlOwner(t)
	s := controlStream(t)
	doubled := append(controlBytes(t, controlStopHex), controlBytes(t, controlStopHex)...)
	s.input = bytes.NewReader(doubled)
	s.write = func(b []byte) (int, error) {
		controlStopped(t, o, g)
		s.mu.Lock()
		s.output = append(s.output, b...)
		s.mu.Unlock()
		return len(b), nil
	}
	out := g.retireControl(s)
	if out != (controlOutcome{Retired: true, AckWritten: true, EndpointClosed: true}) {
		t.Fatal(out)
	}
	if !bytes.Equal(s.bytes(), controlBytes(t, controlAckHex)) || s.input.Len() != 64 || s.closes.Load() != 1 {
		t.Fatal("not exact one-frame exchange")
	}
	controlHeld(t, o, false)
	copyG := *g
	second := controlStream(t)
	if copyG.retireControl(second).Fault != controlClaimed || second.reads.Load()+second.writes.Load()+second.closes.Load() != 0 {
		t.Fatal("second endpoint touched")
	}
}

func TestControlMalformedAndReadFailuresAreFailClosed(t *testing.T) {
	tests := []struct {
		name   string
		setup  func(*controlEndpoint)
		fault  controlFault
		closes int32
	}{
		{"magic", func(s *controlEndpoint) {
			b := controlBytes(t, controlStopHex)
			b[0] = 'X'
			s.input = bytes.NewReader(b)
		}, controlFrame, 1},
		{"opcode", func(s *controlEndpoint) { b := controlBytes(t, controlStopHex); b[8] = 2; s.input = bytes.NewReader(b) }, controlFrame, 1},
		{"reserved", func(s *controlEndpoint) { b := controlBytes(t, controlStopHex); b[9] = 1; s.input = bytes.NewReader(b) }, controlFrame, 1},
		{"suffix", func(s *controlEndpoint) {
			b := controlBytes(t, controlStopHex)
			b[63] = 1
			s.input = bytes.NewReader(b)
		}, controlFrame, 1},
		{"uppercase", func(s *controlEndpoint) {
			b := controlBytes(t, controlStopHex)
			b[16] = 'A'
			s.input = bytes.NewReader(b)
		}, controlFrame, 1},
		{"stale", func(s *controlEndpoint) {
			b := controlBytes(t, controlStopHex)
			b[16] = '1'
			s.input = bytes.NewReader(b)
		}, controlFrame, 1},
		{"epoch0", func(s *controlEndpoint) {
			b := controlBytes(t, controlStopHex)
			b[55] = 0
			s.input = bytes.NewReader(b)
		}, controlFrame, 1},
		{"epoch2", func(s *controlEndpoint) {
			b := controlBytes(t, controlStopHex)
			b[55] = 2
			s.input = bytes.NewReader(b)
		}, controlFrame, 1},
		{"shortEOF", func(s *controlEndpoint) { s.input = bytes.NewReader([]byte("short")) }, controlRead, 1},
		{"negative", func(s *controlEndpoint) { s.read = func([]byte) (int, error) { return -1, nil } }, controlRead, 1},
		{"oversize", func(s *controlEndpoint) { s.read = func(b []byte) (int, error) { return len(b) + 1, nil } }, controlRead, 1},
		{"readError", func(s *controlEndpoint) {
			s.read = func([]byte) (int, error) { return 0, errors.New("fixed synthetic") }
		}, controlRead, 1},
		{"finalError", func(s *controlEndpoint) {
			s.read = func(b []byte) (int, error) {
				copy(b, controlBytes(t, controlStopHex))
				return len(b), errors.New("fixed synthetic")
			}
		}, controlRead, 1},
		{"panic", func(s *controlEndpoint) { s.read = func([]byte) (int, error) { panic("fixed synthetic") } }, controlUnsafe, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			o, g := controlOwner(t)
			s := controlStream(t)
			tc.setup(s)
			out := g.retireControl(s)
			controlStopped(t, o, g)
			controlHeld(t, o, true)
			if out.Fault != tc.fault || !out.Retired || out.AckWritten || s.writes.Load() != 0 || s.closes.Load() != tc.closes {
				t.Fatal(out, s.reads.Load(), s.writes.Load(), s.closes.Load())
			}
			second := controlStream(t)
			if g.retireControl(second).Fault != controlClaimed || second.reads.Load()+second.writes.Load()+second.closes.Load() != 0 {
				t.Fatal("failed attempt retried")
			}
		})
	}
}

func TestControlProgressLimitsAndPartialWrites(t *testing.T) {
	for _, empty := range []int{99, 100} {
		t.Run(string(rune('A'+empty-99)), func(t *testing.T) {
			o, g := controlOwner(t)
			s := controlStream(t)
			calls := 0
			s.read = func(b []byte) (int, error) {
				calls++
				if calls <= empty {
					return 0, nil
				}
				if len(b) > 3 {
					b = b[:3]
				}
				return s.input.Read(b)
			}
			s.write = func(b []byte) (int, error) {
				if len(b) > 5 {
					b = b[:5]
				}
				s.mu.Lock()
				s.output = append(s.output, b...)
				s.mu.Unlock()
				return len(b), nil
			}
			out := g.retireControl(s)
			controlStopped(t, o, g)
			if empty == 100 {
				if out.Fault != controlRead || calls != 100 || s.writes.Load() != 0 {
					t.Fatal(out, calls)
				}
			} else if out.Fault != controlNone || !out.AckWritten || !bytes.Equal(s.bytes(), controlBytes(t, controlAckHex)) {
				t.Fatal(out)
			}
		})
	}
	o, g := controlOwner(t)
	s := controlStream(t)
	s.read = func(b []byte) (int, error) { copy(b, controlBytes(t, controlStopHex)); return len(b), io.EOF }
	if out := g.retireControl(s); !out.AckWritten || out.Fault != controlNone {
		t.Fatal(out)
	}
	controlStopped(t, o, g)
	for _, kind := range []string{"shortError", "negative", "oversize", "finalError", "empty", "panic"} {
		t.Run(kind, func(t *testing.T) {
			o, g := controlOwner(t)
			s := controlStream(t)
			calls := 0
			s.write = func(b []byte) (int, error) {
				calls++
				switch kind {
				case "shortError":
					return 3, io.ErrShortWrite
				case "negative":
					return -1, nil
				case "oversize":
					return len(b) + 1, nil
				case "finalError":
					return len(b), io.ErrShortWrite
				case "empty":
					return 0, nil
				default:
					panic("fixed synthetic")
				}
			}
			out := g.retireControl(s)
			controlStopped(t, o, g)
			controlHeld(t, o, true)
			want := controlWrite
			closes := int32(1)
			if kind == "panic" {
				want = controlUnsafe
				closes = 0
			}
			if out.Fault != want || out.AckWritten || s.closes.Load() != closes || kind == "empty" && calls != 100 || kind != "empty" && calls != 1 {
				t.Fatal(out, calls)
			}
		})
	}
}

func TestControlEmptyProgressResetsForBothDirections(t *testing.T) {
	o, g := controlOwner(t)
	s := controlStream(t)
	reads, writes := 0, 0
	s.read = func(b []byte) (int, error) {
		reads++
		if reads%100 != 0 {
			return 0, nil
		}
		return s.input.Read(b[:1])
	}
	s.write = func(b []byte) (int, error) {
		writes++
		if writes%100 != 0 {
			return 0, nil
		}
		s.mu.Lock()
		s.output = append(s.output, b[0])
		s.mu.Unlock()
		return 1, nil
	}
	out := g.retireControl(s)
	controlStopped(t, o, g)
	if out.Fault != controlNone || !out.AckWritten || reads != 6400 || writes != 6400 || !bytes.Equal(s.bytes(), controlBytes(t, controlAckHex)) {
		t.Fatal(out, reads, writes)
	}
}

func TestControlNilInputAndCloseUncertainty(t *testing.T) {
	var invalid Generation
	s := controlStream(t)
	if invalid.retireControl(s).Fault != controlInput || s.reads.Load()+s.writes.Load()+s.closes.Load() != 0 {
		t.Fatal("invalid generation touched endpoint")
	}
	o, g := controlOwner(t)
	if out := g.retireControl(nil); out.Fault != controlInput || !out.Retired {
		t.Fatal(out)
	}
	controlStopped(t, o, g)
	for _, panics := range []bool{false, true} {
		t.Run(map[bool]string{false: "error", true: "panic"}[panics], func(t *testing.T) {
			o, g := controlOwner(t)
			s := controlStream(t)
			s.close = func() error {
				if panics {
					panic("fixed synthetic")
				}
				return errors.New("fixed synthetic")
			}
			out := g.retireControl(s)
			want := controlClose
			if panics {
				want = controlUnsafe
			}
			if out.Fault != want || !out.AckWritten || out.EndpointClosed || s.closes.Load() != 1 {
				t.Fatal(out)
			}
			controlHeld(t, o, true)
			controlStopped(t, o, g)
		})
	}
}

// Blocked fake calls are owned by a single goroutine with an unconditional gate
// release then explicit result join. No deadline/observer timeout is success.
func controlAsync(t *testing.T, g *Generation, s *controlEndpoint, gates ...*engineGate) <-chan struct{ out controlOutcome } {
	t.Helper()
	done := make(chan struct{ out controlOutcome }, 1)
	joined := make(chan struct{})
	go func() { done <- struct{ out controlOutcome }{g.retireControl(s)}; close(joined) }()
	t.Cleanup(func() {
		for _, gate := range gates {
			gate.open()
		}
		engineReached(t, joined)
	})
	return done
}
func TestControlOnceWhileReadHeldAndCloseHeld(t *testing.T) {
	for _, stage := range []string{"read", "close"} {
		t.Run(stage, func(t *testing.T) {
			o, g := controlOwner(t)
			other, err := o.NewGeneration("10000000000000000000000000000000")
			if err != nil {
				t.Fatal(err)
			}
			s := controlStream(t)
			gate := newEngineGate(t, true)
			if stage == "read" {
				s.read = func(b []byte) (int, error) { gate.wait(); return s.input.Read(b) }
			} else {
				s.close = func() error { gate.wait(); return nil }
			}
			done := controlAsync(t, g, s, gate)
			engineReached(t, gate.entered)
			second := controlStream(t)
			copyG := *other
			if copyG.retireControl(second).Fault != controlClaimed || second.reads.Load()+second.writes.Load()+second.closes.Load() != 0 {
				t.Fatal("second endpoint touched")
			}
			controlHeld(t, o, true)
			if stage == "close" {
				controlStopped(t, o, g)
				if s.writes.Load() != 1 {
					t.Fatal("ACK not written before Close")
				}
			}
			gate.open()
			select {
			case result := <-done:
				if result.out.Fault != controlNone || !result.out.AckWritten {
					t.Fatal(result.out)
				}
			case <-time.After(engineTestBound):
				t.Fatal("released control caller did not return")
			}
		})
	}
}

func TestControlAckDoesNotReleaseActiveEngine(t *testing.T) {
	tx := newEngineTx(t, true, true)
	f := newEngineFactory(t, tx)
	o, g, ctx, _ := engineFixture(t, f)
	j, in := engineBegin(t, o, g, ctx, f, tx, engineBody(t))
	engineReached(t, tx.phase.entered)
	s := controlStream(t)
	s.write = func(b []byte) (int, error) {
		controlStopped(t, o, g)
		engineUsage(t, o, 1, 2)
		if tx.closeCalls.Load() != 0 {
			t.Fatal("Close concurrent with phase")
		}
		s.mu.Lock()
		s.output = append(s.output, b...)
		s.mu.Unlock()
		return len(b), nil
	}
	out := g.retireControl(s)
	if !out.AckWritten || out.Fault != controlNone {
		t.Fatal(out)
	}
	engineUsage(t, o, 1, 2)
	if tx.closeCalls.Load() != 0 {
		t.Fatal("ACK reclaimed transaction")
	}
	tx.phase.open()
	engineReached(t, tx.closing.entered)
	engineUsage(t, o, 1, 2)
	tx.closing.open()
	outJob := engineJoin(t, j)
	if outJob.Recorded || outJob.Engine.InspectionComplete || !outJob.Stopped || !outJob.Retired {
		t.Fatal(outJob)
	}
	_ = in.Close()
	engineUsage(t, o, 0, 0)
}
