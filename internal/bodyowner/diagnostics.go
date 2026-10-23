// SPDX-License-Identifier: BSD-3-Clause
package bodyowner

import "encoding/binary"

const diagnosticFrameSize = 64

type diagnosticBatch struct {
	events                   [4]auditEvent
	n                        int
	lost, overwritten, total uint64
	prejob                   bool
}

// Only the existing accept actor consumes pending slots. A slot is claimed
// before any OS call; failed delivery is loss, never a resend or request tail.
func (o *Owner) takeDiagnostics() (v diagnosticBatch) {
	if o == nil || o.state == nil {
		return v
	}
	s := o.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return v
	}
	a := &s.audit
	v.lost, v.overwritten, v.total, v.prejob = a.lost, a.overwritten, a.total, a.prejob
	for i := uint8(0); i < a.count && v.n < len(v.events); i++ {
		at := (a.next + uint8(len(a.events)) - a.count + i) % uint8(len(a.events))
		if a.pending&(1<<at) == 0 {
			continue
		}
		v.events[v.n] = a.events[at]
		v.n++
		a.pending &^= 1 << at
	}
	return v
}

func (o *Owner) loseDiagnostics(n int) {
	s := o.state
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := 0; i < n; i++ {
		incrementAudit(&s.audit.lost)
	}
}

// Attempt sequence is separate from producer totals, which can saturate. At
// exhaustion no further frame is issued; zero/wrapped sequences never occur.
type diagnosticSequence uint64

func (s *diagnosticSequence) frame(v diagnosticBatch, e auditEvent) (p [diagnosticFrameSize]byte, ok bool) {
	if *s == ^diagnosticSequence(0) {
		return p, false
	}
	*s++
	copy(p[:8], "AGDIAG1\n")
	binary.BigEndian.PutUint64(p[8:16], uint64(*s))
	binary.BigEndian.PutUint64(p[16:24], v.lost)
	binary.BigEndian.PutUint64(p[24:32], v.overwritten)
	binary.BigEndian.PutUint64(p[32:40], v.total)
	p[40], p[41] = e.result, e.flags
	if v.prejob {
		p[42] = 1
	}
	return p, true
}
