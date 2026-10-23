// SPDX-License-Identifier: BSD-3-Clause
package bodyowner

import (
	"encoding/hex"
	"math"
	"testing"
	"unsafe"
)

func TestDiagnosticFrameIndependentLiteral(t *testing.T) {
	// Frozen before production edits in aegvium-diagnostics-freeze-20261023.json.
	want := "414744494147310a0000000000000001000000000000000200000000000000030000000000000004050701000000000000000000000000000000000000000000"
	var s diagnosticSequence
	p, ok := s.frame(diagnosticBatch{lost: 2, overwritten: 3, total: 4, prejob: true}, auditEvent{5, 7})
	if !ok || len(p) != 64 || hex.EncodeToString(p[:]) != want {
		t.Fatal("independent diagnostic frame mismatch")
	}
	s = diagnosticSequence(math.MaxUint64)
	if _, ok = s.frame(diagnosticBatch{}, auditEvent{}); ok {
		t.Fatal("sequence exhausted but wrapped")
	}
}

func TestDiagnosticPendingCursorSurvivesSaturation(t *testing.T) {
	o := New()
	s := o.state
	if unsafe.Sizeof(s.audit) > 64 {
		t.Fatal("producer logical budget exceeded")
	}
	// Unique fixed flags make independent FIFO assertions even for equal classes.
	for i := 0; i < 18; i++ {
		s.recordDataOutcome(Outcome{})
		s.audit.events[(s.audit.next+15)%16].flags = uint8(i)
	}
	if s.audit.lost != 2 || s.audit.overwritten != 2 {
		t.Fatal("pending overwrite loss missing")
	}
	s.audit.total = math.MaxUint64
	s.audit.overwritten = math.MaxUint64
	for group := 0; group < 4; group++ {
		v := o.takeDiagnostics()
		if v.n != 4 || v.total != math.MaxUint64 {
			t.Fatal("bounded independent cursor")
		}
		for i := 0; i < 4; i++ {
			if v.events[i].flags != uint8(2+group*4+i) {
				t.Fatal("lost order or duplicate")
			}
		}
	}
	if o.takeDiagnostics().n != 0 {
		t.Fatal("duplicate delivery after drain")
	}
	s.recordDataOutcome(Outcome{})
	if o.takeDiagnostics().n != 1 || o.takeDiagnostics().n != 0 {
		t.Fatal("new event lost after total saturation")
	}
	s.audit.lost = math.MaxUint64
	o.loseDiagnostics(4)
	if s.audit.lost != math.MaxUint64 {
		t.Fatal("loss counter wrapped")
	}
	s.recordDataOutcome(Outcome{})
	o.Stop()
	if o.takeDiagnostics().n != 0 || s.audit.pending == 0 {
		t.Fatal("stop drained or erased pending diagnostic")
	}
}
