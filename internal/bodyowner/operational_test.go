// SPDX-License-Identifier: BSD-3-Clause
package bodyowner

import (
	"errors"
	"math"
	"strconv"
	"strings"
	"testing"
	"unsafe"
)

func requireOperational(t *testing.T, o *Owner, want ...string) string {
	t.Helper()
	report := o.OperationalReport()
	if len(report) > 4096 || !strings.HasPrefix(report, "aegvium-status-v1 qualified=0 ") {
		t.Fatal("invalid bounded unqualified status")
	}
	for _, text := range want {
		if !strings.Contains(report, text) {
			t.Fatalf("missing fixed status %q", text)
		}
	}
	return report
}

func TestOperationalReportKeepsHeldCleanupCharged(t *testing.T) {
	tx := newEngineTx(t, true, true)
	o, g, ctx, _ := engineFixture(t, newEngineFactory(t, tx))
	s := newOwnedData(t)
	s.exchange = newEngineGate(t, true)
	s.closing = newEngineGate(t, true)
	j := beginOwnedData(t, o, g, ctx, tx, s)
	engineReached(t, tx.phase.entered)
	requireOperational(t, o, "engine=active_source", "requests=1 sockets=2 active=1 retained=0 tx=1", "events=0 overwritten=0")
	tx.phase.open()
	engineReached(t, s.exchange.entered)
	requireOperational(t, o, "requests=1 sockets=2 active=1 retained=0 tx=1", "events=0 overwritten=0")
	s.exchange.open()
	engineReached(t, s.closing.entered)
	requireOperational(t, o, "events=0 overwritten=0")
	s.closing.open()
	engineReached(t, tx.closing.entered)
	requireOperational(t, o, "requests=1 sockets=2 active=1 retained=0 tx=1", "events=0 overwritten=0")
	tx.closing.open()
	engineJoin(t, j)
	first := requireOperational(t, o, "requests=0 sockets=0 active=0 retained=0 tx=0", "events=1 overwritten=0", "event result=response_written backend=possible response=written cleanup=certain canceled=0 retired=0 stopped=0\n")
	if second := o.OperationalReport(); first != second {
		t.Fatal("reading changed status")
	}
	engineUsage(t, o, 0, 0)
}

func TestOperationalReportPreservesUncertainAndRedacts(t *testing.T) {
	for _, mode := range []string{"close", "backend", "input", "policy", "phase"} {
		t.Run(mode, func(t *testing.T) {
			tx := newEngineTx(t, false, false)
			tx.headerReject = mode == "policy"
			tx.bodyError = mode == "phase"
			o, g, ctx, _ := engineFixture(t, newEngineFactory(t, tx))
			s := newOwnedData(t)
			secret := "Synthetic_Private_Metadata"
			s.row.RequestID = secret
			s.row.Target = "/a?private=" + secret
			s.row.Body = []byte(secret)
			s.row.Fields[2].Value = strconv.Itoa(len(s.row.Body))
			if mode == "close" {
				s.closeErr = errors.New(secret)
				s.uncertain = true
			}
			if mode == "backend" {
				s.exchangeErr = errors.New(secret)
			}
			if mode == "input" {
				s.readErr = errors.New(secret)
			}
			j := beginOwnedData(t, o, g, ctx, tx, s)
			engineJoin(t, j)
			report := requireOperational(t, o, "events=1 overwritten=0")
			if strings.Contains(report, secret) || strings.Contains(report, "app.test") || strings.Contains(report, "192.0.2.") || strings.Contains(report, engineTestGeneration) {
				t.Fatal("private metadata escaped fixed fields")
			}
			switch mode {
			case "close":
				requireOperational(t, o, "engine=cleanup_only stopped=1", "requests=1 sockets=2 active=0 retained=1 tx=1", "result=response_written backend=possible response=written cleanup=uncertain")
				engineUsage(t, o, 1, 2)
			case "backend":
				requireOperational(t, o, "result=backend_unknown backend=possible response=unwritten cleanup=certain")
				engineUsage(t, o, 0, 0)
			case "input":
				requireOperational(t, o, "result=input_rejected backend=none response=unwritten cleanup=certain")
			case "phase":
				requireOperational(t, o, "result=inspection_error backend=none response=unwritten cleanup=certain")
				if s.attempts.Load() != 0 {
					t.Fatal("failed phase reached backend")
				}
			case "policy":
				requireOperational(t, o, "result=policy_rejected backend=none response=unwritten cleanup=certain")
			}
		})
	}
}

func TestOperationalReportRingBoundAndSaturation(t *testing.T) {
	txs := make([]*engineTx, 18)
	for i := range txs {
		txs[i] = newEngineTx(t, false, false)
		txs[i].headerReject = i < 4
	}
	o, g, ctx, _ := engineFixture(t, newEngineFactory(t, txs...))
	for _, tx := range txs {
		s := newOwnedData(t)
		j := beginOwnedData(t, o, g, ctx, tx, s)
		engineJoin(t, j)
	}
	report := requireOperational(t, o, "events=18 overwritten=2")
	lines := strings.Split(strings.TrimSuffix(report, "\n"), "\n")
	if len(lines) != 17 {
		t.Fatal("history did not stay at sixteen")
	}
	for i, line := range lines[1:] {
		want := "result=response_written"
		if i < 2 {
			want = "result=policy_rejected"
		}
		if !strings.Contains(line, want) {
			t.Fatal("history order changed")
		}
	}
	if unsafe.Sizeof(auditHistory{}) > 64 {
		t.Fatal("persistent logical audit budget exceeded")
	}
	o.state.mu.Lock()
	o.state.audit.total = math.MaxUint64
	o.state.audit.overwritten = math.MaxUint64
	o.state.mu.Unlock()
	// Use one real additional DATA job, not a detached record issuer.
	tx := newEngineTx(t, false, false)
	tx.headerReject = true
	f := o.state.engine.factory.(*engineFactory)
	f.mu.Lock()
	f.transactions = append(f.transactions, tx)
	f.mu.Unlock()
	j := beginOwnedData(t, o, g, ctx, tx, newOwnedData(t))
	engineJoin(t, j)
	report = requireOperational(t, o, "events=18446744073709551615 overwritten=18446744073709551615")
	lines = strings.Split(strings.TrimSuffix(report, "\n"), "\n")
	if !strings.Contains(lines[len(lines)-1], "result=policy_rejected") {
		t.Fatal("saturation froze newest event")
	}
}

func TestOperationalReportStopAndCacheUncertaintyStayDiagnostic(t *testing.T) {
	var absent *Owner
	requireOperational(t, absent, "engine=absent")
	requireOperational(t, New(), "engine=absent")
	o, g, _, _ := engineFixture(t, newEngineFactory(t))
	o.Stop()
	g.Retire()
	engineReached(t, o.state.engine.cacheDone)
	requireOperational(t, o, "engine=cleanup_only stopped=1 retired=1", "cache=released")
	o.state.mu.Lock()
	o.state.engine.cacheReleased = false
	o.state.engine.cacheUncertain = true
	o.state.mu.Unlock()
	report := requireOperational(t, o, "cache=uncertain")
	if strings.Contains(report, "ready=") || strings.Contains(report, "healthy=") || strings.Contains(report, "qualified=1") {
		t.Fatal("diagnostic status minted readiness")
	}
}
