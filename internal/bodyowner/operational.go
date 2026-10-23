// SPDX-License-Identifier: BSD-3-Clause
package bodyowner

import "strconv"

const MaxOperationalReport = 4096

// These records contain only classifications from the actual returned DATA job.
// No strings, request metadata, pointers or transport/provider handles are held.
type auditEvent struct{ result, flags uint8 }
type auditHistory struct {
	events             [16]auditEvent
	total, overwritten uint64
	next, count        uint8
	prejob             bool // Sticky actual pre-job transport cleanup uncertainty.
}

const (
	auditNotForwarded uint8 = iota
	auditInputRejected
	auditPolicyRejected
	auditInspectionError
	auditBackendUnknown
	auditResponseWritten
)
const (
	auditPossible uint8 = 1 << iota
	auditWritten
	auditCertain
	auditCanceled
	auditRetired
	auditStopped
)

func incrementAudit(value *uint64) {
	if *value != ^uint64(0) {
		*value++
	}
}

// owner.mu is held. This is the same worker's final observation, including a
// returned but retained uncertain outcome; it never creates reclamation proof.
func (s *ownerState) recordDataOutcome(out Outcome) {
	e := out.Engine
	var event auditEvent
	switch {
	case e.ResponseWritten:
		event.result = auditResponseWritten
	case e.BackendEffect == "PossiblyEffected":
		event.result = auditBackendUnknown
	case out.ReadFailure != None:
		event.result = auditInputRejected
	case e.Fault == EngineRejected:
		event.result = auditPolicyRejected
	case e.Fault != EngineNone:
		event.result = auditInspectionError
	}
	for _, flag := range []struct {
		set bool
		bit uint8
	}{{e.BackendEffect == "PossiblyEffected", auditPossible}, {e.ResponseWritten, auditWritten}, {e.CleanupCertain, auditCertain}, {out.Canceled, auditCanceled}, {out.Retired, auditRetired}, {out.Stopped, auditStopped}} {
		if flag.set {
			event.flags |= flag.bit
		}
	}
	a := &s.audit
	a.events[a.next] = event
	a.next = (a.next + 1) % uint8(len(a.events))
	if a.count < uint8(len(a.events)) {
		a.count++
	} else {
		incrementAudit(&a.overwritten)
	}
	incrementAudit(&a.total)
}

type operationalSnapshot struct {
	audit                                             auditHistory
	engine, cache                                     uint8
	stopped, retired                                  bool
	requests, sockets, active, retained, transactions int
}

func (o *Owner) operationalSnapshot() (v operationalSnapshot) {
	if o == nil || o.state == nil {
		return v
	}
	s := o.state
	s.mu.Lock()
	defer s.mu.Unlock()
	v.audit, v.stopped = s.audit, s.stopped
	usage := s.slots.Usage()
	v.requests, v.sockets = usage.Requests, usage.Sockets
	for job := range s.jobs {
		if job.outcome.Joined {
			v.retained++
		} else {
			v.active++
		}
	}
	if e := s.engine; e != nil {
		v.engine = uint8(e.mode) + 1
		v.retired, v.transactions = e.retired, e.references
		switch {
		case e.cacheUncertain:
			v.cache = 3
		case e.cacheReleased:
			v.cache = 2
		case e.cacheCloseStarted:
			v.cache = 1
		}
	}
	return v
}

// reportText has fixed storage and accepts only private fixed literals and
// numbers. There is no sink, callback, filesystem, flush or blocking I/O.
type reportText struct {
	bytes [MaxOperationalReport]byte
	n     int
	full  bool
}

func (b *reportText) text(s string) {
	if len(s) > len(b.bytes)-b.n {
		b.full = true
		return
	}
	b.n += copy(b.bytes[b.n:], s)
}
func (b *reportText) number(n uint64) {
	var digits [20]byte
	b.text(string(strconv.AppendUint(digits[:0], n, 10)))
}
func (b *reportText) bit(flag bool) {
	if flag {
		b.text("1")
	} else {
		b.text("0")
	}
}
func (b *reportText) choice(flag bool, yes, no string) {
	if flag {
		b.text(yes)
	} else {
		b.text(no)
	}
}

// OperationalReport copies actual bounded state under the owner lock and
// formats only after unlocking. It cannot admit, stop, clear or refund work.
// Qualification is always zero; active_source is not readiness or native proof.
func (o *Owner) OperationalReport() string {
	v := o.operationalSnapshot()
	var b reportText
	b.text("aegvium-status-v1 qualified=0 engine=")
	switch v.engine {
	case 1:
		b.text("active_source")
	case 2:
		b.text("cleanup_only")
	case 3:
		b.text("unsafe")
	default:
		b.text("absent")
	}
	b.text(" stopped=")
	b.bit(v.stopped)
	b.text(" retired=")
	b.bit(v.retired)
	for _, field := range []struct {
		name  string
		value int
	}{{" requests=", v.requests}, {" sockets=", v.sockets}, {" active=", v.active}, {" retained=", v.retained}, {" tx=", v.transactions}} {
		b.text(field.name)
		b.number(uint64(field.value))
	}
	b.text(" prejob=")
	b.choice(v.audit.prejob, "retained", "none")
	b.text(" cache=")
	switch v.cache {
	case 1:
		b.text("closing")
	case 2:
		b.text("released")
	case 3:
		b.text("uncertain")
	default:
		b.choice(v.engine != 0, "held", "absent")
	}
	b.text(" events=")
	b.number(v.audit.total)
	b.text(" overwritten=")
	b.number(v.audit.overwritten)
	b.text("\n")
	for i := uint8(0); i < v.audit.count; i++ {
		e := v.audit.events[(v.audit.next+uint8(len(v.audit.events))-v.audit.count+i)%uint8(len(v.audit.events))]
		b.text("event result=")
		switch e.result {
		case auditInputRejected:
			b.text("input_rejected")
		case auditPolicyRejected:
			b.text("policy_rejected")
		case auditInspectionError:
			b.text("inspection_error")
		case auditBackendUnknown:
			b.text("backend_unknown")
		case auditResponseWritten:
			b.text("response_written")
		default:
			b.text("not_forwarded")
		}
		b.text(" backend=")
		b.choice(e.flags&auditPossible != 0, "possible", "none")
		b.text(" response=")
		b.choice(e.flags&auditWritten != 0, "written", "unwritten")
		b.text(" cleanup=")
		b.choice(e.flags&auditCertain != 0, "certain", "uncertain")
		b.text(" canceled=")
		b.bit(e.flags&auditCanceled != 0)
		b.text(" retired=")
		b.bit(e.flags&auditRetired != 0)
		b.text(" stopped=")
		b.bit(e.flags&auditStopped != 0)
		b.text("\n")
	}
	if b.full {
		return "aegvium-status-v1 qualified=0 engine=unavailable report=overflow\n"
	}
	return string(b.bytes[:b.n])
}
