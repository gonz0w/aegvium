// SPDX-License-Identifier: BSD-3-Clause
package bodyowner

import (
	"encoding/binary"
	"io"
	"os"
)

const controlFrameSize = 64
const controlMagic = "AGCTRL1\n"

type controlFault string

const (
	controlNone    controlFault = ""
	controlInput   controlFault = "Input"
	controlClaimed controlFault = "Claimed"
	controlRead    controlFault = "Read"
	controlFrame   controlFault = "Frame"
	controlWrite   controlFault = "Write"
	controlClose   controlFault = "Close"
	controlUnsafe  controlFault = "Unsafe"
)

// Admission retirement only. None of these fields proves S's own descriptor
// closure, process reclamation, clean jobs, generation readiness or allow.
type controlOutcome struct {
	Retired, AckWritten, EndpointClosed bool
	Fault                               controlFault
}

// A source binding only, with no caller and no inherited-FD authentication.
// Future sole-launch bootstrap must supply the actual exclusively owned channel.
func (g *Generation) retireInheritedControl(endpoint *os.File) controlOutcome {
	if endpoint == nil {
		return g.retireControl(nil)
	}
	return g.retireControl(endpoint)
}

// retireControl consumes one attempt per actual owner before endpoint I/O. It
// creates no worker/timeout and waits for no body/engine cleanup. Stuck I/O stays
// owned. Calls and Close occur outside owner.mu; panic permits no later call.
func (g *Generation) retireControl(endpoint io.ReadWriteCloser) controlOutcome {
	if g == nil || g.state == nil || g.state.owner == nil || g.state.slots == nil || len(g.state.token) != 32 {
		return controlOutcome{Fault: controlInput}
	}
	s := g.state.owner
	s.mu.Lock()
	if s.controlClaimed {
		s.mu.Unlock()
		return controlOutcome{Fault: controlClaimed}
	}
	s.controlClaimed, s.control = true, endpoint
	s.mu.Unlock()
	out := controlOutcome{}
	retire := func() {
		(&Owner{state: s}).Stop()
		g.Retire()
		out.Retired = true
	}
	if endpoint == nil {
		retire()
		out.Fault = controlInput
		return out
	}
	var frame [controlFrameSize]byte
	complete, panicked := transferControl(endpoint.Read, frame[:], true)
	if panicked {
		retire()
		out.Fault = controlUnsafe
		return out
	}
	if !complete {
		out.Fault = controlRead
	} else if !g.matchesControl(frame) {
		out.Fault = controlFrame
	}
	retire() // Both actual admission marks precede the first ACK byte, even on faults.
	if out.Fault == controlNone {
		frame[8] = 2
		complete, panicked = transferControl(endpoint.Write, frame[:], false)
		if panicked {
			out.Fault = controlUnsafe
			return out
		}
		if !complete {
			out.Fault = controlWrite
		} else {
			out.AckWritten = true
		}
	}
	var err error
	if invoke(func() { err = endpoint.Close() }) {
		out.Fault = controlUnsafe
		return out
	}
	if err != nil {
		if out.Fault == controlNone {
			out.Fault = controlClose
		}
		return out
	}
	out.EndpointClosed = true // I's endpoint only, never an S protocol-close event.
	if out.Fault == controlNone {
		s.mu.Lock()
		s.control = nil
		s.mu.Unlock()
	}
	// Failed endpoints remain in the one owner slot even after ordinary Close.
	return out
}

func (g *Generation) matchesControl(frame [controlFrameSize]byte) bool {
	if string(frame[:8]) != controlMagic || frame[8] != 1 || string(frame[16:48]) != g.state.token || binary.BigEndian.Uint64(frame[48:56]) != 1 {
		return false
	}
	for _, value := range frame[9:16] {
		if value != 0 {
			return false
		}
	}
	for _, value := range frame[56:] {
		if value != 0 {
			return false
		}
	}
	return true
}

// No call may write outside the remaining fixed frame, and each run of exactly
// 100 empty operations fails. A non-EOF error refuses even with the final bytes;
// exact input+EOF is complete, but any output error is not a complete ACK.
func transferControl(call func([]byte) (int, error), frame []byte, reading bool) (bool, bool) {
	total, empty := 0, 0
	for total < len(frame) {
		var n int
		var err error
		if invoke(func() { n, err = call(frame[total:]) }) {
			return false, true
		}
		if n < 0 || n > len(frame)-total {
			return false, false
		}
		total += n
		if err != nil {
			return reading && err == io.EOF && total == len(frame), false
		}
		if n == 0 {
			empty++
			if empty == 100 {
				return false, false
			}
		} else {
			empty = 0
		}
	}
	return true, false
}
