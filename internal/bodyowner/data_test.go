// SPDX-License-Identifier: BSD-3-Clause
package bodyowner

// Actual pinned Transaction API fake + intercepted transport calls only.
// Every held call has unconditional release/join; no socket/TLS/engine runs.
import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gonz0w/aegvium/internal/requestctx"
)

type ownedDataFixture struct {
	read, exchange, closing          *engineGate
	reads, attempts, closes, rejects atomic.Int32
	status                           atomic.Int32
	row                              requestctx.Record
	readErr, exchangeErr, closeErr   error
	uncertain, unsafe                bool
	panicAt                          string
	onCall                           func(string)
}

func newOwnedData(t *testing.T) *ownedDataFixture {
	in := engineMetadata()
	return &ownedDataFixture{read: newEngineGate(t, false), exchange: newEngineGate(t, false), closing: newEngineGate(t, false), row: requestctx.Record{Generation: engineTestGeneration, PolicyPin: strings.Repeat("01", 32), RequestID: in.id, SNI: in.sni, Protocol: in.protocol, Method: in.method, Target: in.target, Remote: in.client, Local: in.server, PublicPort: in.publicPort, Fields: in.fields, Body: []byte("{}")}}
}
func (s *ownedDataFixture) note(n string) {
	if s.onCall != nil {
		s.onCall(n)
	}
	if s.panicAt == n {
		panic("synthetic DATA boundary panic")
	}
}
func (s *ownedDataFixture) ReadDataSource(context.Context) (requestctx.Record, error) {
	s.reads.Add(1)
	s.note("read")
	s.read.wait()
	return s.row, s.readErr
}
func (s *ownedDataFixture) ExchangeDataSource(context.Context) (bool, bool, error) {
	s.attempts.Add(1)
	s.note("exchange")
	s.exchange.wait()
	return true, s.exchangeErr == nil, s.exchangeErr
}
func (s *ownedDataFixture) RejectDataSource(_ context.Context, code int) error {
	s.status.Store(int32(code))
	s.rejects.Add(1)
	s.note("reject")
	return nil
}
func (s *ownedDataFixture) CloseDataSource() error {
	s.closes.Add(1)
	s.note("close")
	s.closing.wait()
	return s.closeErr
}
func (s *ownedDataFixture) CleanupDataSource() (bool, bool) {
	s.note("cleanup")
	return !s.uncertain, s.unsafe
}

func beginOwnedData(t *testing.T, o *Owner, g *Generation, ctx context.Context, tx *engineTx, s *ownedDataFixture) *Job {
	t.Helper()
	o.state.mu.Lock()
	o.state.engine.policy = &ownedPolicy{pin: strings.Repeat("01", 32), ruleCount: 1}
	o.state.mu.Unlock()
	in, err := o.ReserveInbound()
	if err != nil {
		t.Fatal(err)
	}
	j, err := g.beginOwned(ctx, in, nil, 0, nil, s, false)
	if err != nil {
		_ = in.Close()
		t.Fatal(err)
	}
	if in.Close() != ErrTransferred {
		t.Fatal("DATA lease did not transfer pre-accept charge")
	}
	t.Cleanup(func() {
		s.read.open()
		s.exchange.open()
		s.closing.open()
		if tx != nil {
			tx.releaseAll()
		}
		engineJoin(t, j)
	})
	return j
}

func TestDataSameLeaseTransactionThroughExchangeAndCleanup(t *testing.T) {
	tx := newEngineTx(t, true, true)
	f := newEngineFactory(t, tx)
	o, g, ctx, _ := engineFixture(t, f)
	s := newOwnedData(t)
	s.exchange = newEngineGate(t, true)
	s.closing = newEngineGate(t, true)
	j := beginOwnedData(t, o, g, ctx, tx, s)
	engineReached(t, tx.phase.entered)
	engineUsage(t, o, 1, 2)
	if s.attempts.Load() != 0 || tx.logCalls.Load() != 0 || tx.closeCalls.Load() != 0 {
		t.Fatal("effect/cleanup before inspection")
	}
	tx.phase.open()
	engineReached(t, s.exchange.entered)
	engineUsage(t, o, 1, 2)
	if tx.logCalls.Load() != 0 || tx.closeCalls.Load() != 0 || j.Outcome().Engine.BackendEffect != "PossiblyEffected" {
		t.Fatal("tx/lease released during backend")
	}
	s.exchange.open()
	engineReached(t, s.closing.entered)
	engineUsage(t, o, 1, 2)
	if tx.logCalls.Load() != 0 || tx.closeCalls.Load() != 0 {
		t.Fatal("logging/txClose before network cleanup joined")
	}
	s.closing.open()
	engineReached(t, tx.closing.entered)
	engineUsage(t, o, 1, 2)
	if tx.logCalls.Load() != 1 || s.closes.Load() != 1 {
		t.Fatal("terminal order/once cleanup")
	}
	tx.closing.open()
	out := engineJoin(t, j)
	engineUsage(t, o, 0, 0)
	if !out.Engine.ResponseWritten || !out.Engine.ExchangeReturned || !out.Engine.CleanupCertain || !out.Engine.Released || s.attempts.Load() != 1 || s.rejects.Load() != 0 {
		t.Fatal("one exchange not completed under owned job")
	}
}

func TestDataDenialAndCancellationCannotStartBackend(t *testing.T) {
	for _, mode := range []string{"denied", "cancel", "retire", "bad-generation", "bad-policy", "read-error"} {
		t.Run(mode, func(t *testing.T) {
			tx := newEngineTx(t, mode == "cancel" || mode == "retire", false)
			tx.headerReject = mode == "denied"
			f := newEngineFactory(t, tx)
			o, g, ctx, cancel := engineFixture(t, f)
			s := newOwnedData(t)
			if mode == "bad-generation" {
				s.row.Generation = strings.Repeat("f", 32)
			}
			if mode == "bad-policy" {
				s.row.PolicyPin = strings.Repeat("f", 64)
			}
			if mode == "read-error" {
				s.readErr = errors.New("fixed read")
			}
			j := beginOwnedData(t, o, g, ctx, tx, s)
			if mode == "cancel" || mode == "retire" {
				engineReached(t, tx.phase.entered)
				if mode == "cancel" {
					cancel()
				} else {
					g.Retire()
				}
				tx.phase.open()
			}
			out := engineJoin(t, j)
			engineUsage(t, o, 0, 0)
			if s.attempts.Load() != 0 || out.Engine.BackendEffect != "NoBackendAttempt" || s.closes.Load() != 1 {
				t.Fatal("failed/cancelled context reached backend or released early")
			}
		})
	}
}

func TestDataAttemptFailureNeverRetriesAndUncertaintyRetains(t *testing.T) {
	for _, mode := range []string{"backend-error", "close-error", "unknown-cleanup", "panic-exchange", "panic-close", "unsafe-cleanup"} {
		t.Run(mode, func(t *testing.T) {
			tx := newEngineTx(t, false, false)
			f := newEngineFactory(t, tx)
			o, g, ctx, _ := engineFixture(t, f)
			s := newOwnedData(t)
			switch mode {
			case "backend-error":
				s.exchangeErr = errors.New("fixed backend")
			case "close-error":
				s.closeErr = errors.New("fixed close")
				s.uncertain = true
			case "unknown-cleanup":
				s.uncertain = true
			case "panic-exchange":
				s.panicAt = "exchange"
			case "panic-close":
				s.panicAt = "close"
			case "unsafe-cleanup":
				s.unsafe = true
				s.uncertain = true
			}
			j := beginOwnedData(t, o, g, ctx, tx, s)
			out := engineJoin(t, j)
			if s.attempts.Load() != 1 || out.Engine.BackendEffect != "PossiblyEffected" {
				t.Fatal("attempt retried/lost possible effect")
			}
			if mode == "backend-error" {
				engineUsage(t, o, 0, 0)
				if s.rejects.Load() != 1 {
					t.Fatal("bounded502 missing")
				}
			} else {
				engineUsage(t, o, 1, 2)
				if out.Engine.CleanupCertain || out.Engine.Released {
					t.Fatal("uncertain cleanup refunded")
				}
				o.state.mu.Lock()
				held := j.state.transaction != nil && o.state.engine.references == 1
				o.state.mu.Unlock()
				if !held || tx.closeCalls.Load() != 0 || tx.logCalls.Load() != 0 {
					t.Fatal("uncertain socket cleanup lost the SAME transaction")
				}
			}
			if strings.HasPrefix(mode, "panic") || mode == "unsafe-cleanup" {
				if tx.closeCalls.Load() != 0 {
					t.Fatal("engine used after unsafe boundary")
				}
			}
		})
	}
}

func TestDataRetirementWaitsForActualBackendAndTransaction(t *testing.T) {
	tx := newEngineTx(t, false, true)
	f := newEngineFactory(t, tx)
	o, g, ctx, _ := engineFixture(t, f)
	s := newOwnedData(t)
	s.exchange = newEngineGate(t, true)
	j := beginOwnedData(t, o, g, ctx, tx, s)
	engineReached(t, s.exchange.entered)
	g.Retire()
	engineReached(t, s.closing.entered)
	if f.closes.Load() != 0 || tx.closeCalls.Load() != 0 {
		t.Fatal("retirement freed held backend/tx")
	}
	s.exchange.open()
	engineReached(t, tx.closing.entered)
	engineUsage(t, o, 1, 2)
	if f.closes.Load() != 0 {
		t.Fatal("WAF closed before tx Close return")
	}
	tx.closing.open()
	engineJoin(t, j)
	g.Retire()
	engineReached(t, o.state.engine.cacheDone)
	if f.closes.Load() != 1 || s.attempts.Load() != 1 {
		t.Fatal("retirement duplicate/missing closure")
	}
}

func TestDataSharedCapacityDoesNotCreateFifthWorker(t *testing.T) {
	txs := []*engineTx{newEngineTx(t, false, false), newEngineTx(t, false, false), newEngineTx(t, false, false), newEngineTx(t, false, false)}
	f := newEngineFactory(t, txs...)
	o, g, ctx, _ := engineFixture(t, f)
	var jobs []*Job
	var sessions []*ownedDataFixture
	for _, tx := range txs {
		s := newOwnedData(t)
		s.read = newEngineGate(t, true)
		sessions = append(sessions, s)
		jobs = append(jobs, beginOwnedData(t, o, g, ctx, tx, s))
		engineReached(t, s.read.entered)
	}
	engineUsage(t, o, 4, 8)
	if _, err := o.ReserveInbound(); err != ErrCapacity {
		t.Fatal("ninth accepted socket allowed")
	}
	for _, s := range sessions {
		s.read.open()
	}
	for _, j := range jobs {
		engineJoin(t, j)
	}
	engineUsage(t, o, 0, 0)
}

func TestDataReadFailureStatusRetainsClassificationWithoutBackend(t *testing.T) {
	for _, tc := range []struct {
		err    error
		status int32
	}{
		{requestctx.ErrDataInput, 400}, {requestctx.ErrDataHeaderLimit, 431},
		{requestctx.ErrDataBodyLimit, 413}, {requestctx.ErrDataAuthority, 421},
		{requestctx.ErrDataForbidden, 403}, {requestctx.ErrDataUnavailable, 503},
	} {
		t.Run(tc.err.Error(), func(t *testing.T) {
			tx := newEngineTx(t, false, false)
			f := newEngineFactory(t, tx)
			o, g, ctx, _ := engineFixture(t, f)
			s := newOwnedData(t)
			s.readErr = tc.err
			j := beginOwnedData(t, o, g, ctx, tx, s)
			engineJoin(t, j)
			if s.status.Load() != tc.status || s.attempts.Load() != 0 || s.rejects.Load() != 1 || tx.logCalls.Load() != 0 || tx.closeCalls.Load() != 0 {
				t.Fatal("failure classification lost or inspection/backend started")
			}
			engineUsage(t, o, 0, 0)
		})
	}
}
