// SPDX-License-Identifier: BSD-3-Clause
package bodyowner

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/corazawaf/coraza/v3/collection"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/gonz0w/aegvium/internal/requestctx"
)

const engineTestBound = 2 * time.Second
const engineTestGeneration = "00000000000000000000000000000000"

// All controlled calls are releasable independently of the implementation.
// Each admitted fixture registers unconditional release AND explicit job join.
type engineGate struct {
	entered, release chan struct{}
	enterOnce, free  sync.Once
}

func newEngineGate(t *testing.T, held bool) *engineGate {
	g := &engineGate{entered: make(chan struct{}), release: make(chan struct{})}
	if !held {
		g.open()
	}
	t.Cleanup(g.open)
	return g
}
func (g *engineGate) wait() { g.enterOnce.Do(func() { close(g.entered) }); <-g.release }
func (g *engineGate) open() { g.free.Do(func() { close(g.release) }) }
func engineReached(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(engineTestBound):
		t.Fatal("finite fake barrier did not return")
	}
}

type engineTrace struct {
	mu        sync.Mutex
	calls     []string
	postClose atomic.Int32
}

func (r *engineTrace) add(value string) { r.mu.Lock(); r.calls = append(r.calls, value); r.mu.Unlock() }
func (r *engineTrace) rows() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.calls...)
}

type engineSingle struct {
	collection.Single
	tx          *engineTx
	name, value string
}

func (s *engineSingle) Get() string { s.tx.note("get:" + s.name); return s.value }

type engineVars struct {
	plugintypes.TransactionVariables
	tx  *engineTx
	bad string
}

func (v *engineVars) one(name string) collection.Single {
	v.tx.note("var:" + name)
	value := "0"
	if v.bad == name {
		value = "1"
	}
	return &engineSingle{tx: v.tx, name: name, value: value}
}
func (v *engineVars) InboundDataError() collection.Single          { return v.one("inbound") }
func (v *engineVars) RequestBodyError() collection.Single          { return v.one("body") }
func (v *engineVars) RequestBodyProcessorError() collection.Single { return v.one("processor") }
func (v *engineVars) UrlencodedError() collection.Single           { return v.one("urlencoded") }
func (v *engineVars) ArgumentsLimitReached() collection.Single     { return v.one("arguments") }
func (v *engineVars) URIParseError() collection.Single             { return v.one("uri") }

// Embedding implements the full actual pinned API. An unexpected method invokes
// a nil interface and becomes Unsafe, which every ordinary fixture rejects.
type engineTx struct {
	types.Transaction
	trace                                                           engineTrace
	headers, phase, logging, closing                                *engineGate
	logCalls, closeCalls                                            atomic.Int32
	closed                                                          atomic.Bool
	last                                                            types.RulePhase
	vars                                                            *engineVars
	headerReject, bodyError, shortWrite, off, inaccessible, nilVars bool
	panicAt                                                         string
	closeError                                                      error
	hook                                                            func(string)
}

func newEngineTx(t *testing.T, holdPhase, holdClose bool) *engineTx {
	tx := &engineTx{headers: newEngineGate(t, false), phase: newEngineGate(t, holdPhase), logging: newEngineGate(t, false), closing: newEngineGate(t, holdClose)}
	tx.vars = &engineVars{tx: tx}
	return tx
}
func (tx *engineTx) note(value string) {
	if tx.closed.Load() {
		tx.trace.postClose.Add(1)
	}
	tx.trace.add(value)
	if tx.hook != nil {
		tx.hook(value)
	}
	if tx.panicAt == value {
		panic("fixed synthetic panic")
	}
}
func (tx *engineTx) Variables() plugintypes.TransactionVariables {
	tx.note("variables")
	if tx.nilVars {
		return nil
	}
	return tx.vars
}
func (tx *engineTx) LastPhase() types.RulePhase { tx.note("last"); return tx.last }
func (tx *engineTx) ProcessConnection(c string, cp int, s string, sp int) {
	tx.note("connection:" + c + ":" + strconv.Itoa(cp) + ":" + s + ":" + strconv.Itoa(sp))
}
func (tx *engineTx) ProcessURI(target, method, version string) {
	tx.note("uri:" + target + ":" + method + ":" + version)
}
func (tx *engineTx) SetServerName(name string)           { tx.note("sni:" + name) }
func (tx *engineTx) AddRequestHeader(name, value string) { tx.note("header:" + name + ":" + value) }
func (tx *engineTx) IsRuleEngineOff() bool               { tx.note("off"); return tx.off }
func (tx *engineTx) IsRequestBodyAccessible() bool       { tx.note("access"); return !tx.inaccessible }
func (tx *engineTx) IsInterrupted() bool                 { tx.note("interrupted"); return false }
func (tx *engineTx) ProcessRequestHeaders() *types.Interruption {
	tx.note("headers")
	tx.headers.wait()
	tx.last = types.PhaseRequestHeaders
	if tx.headerReject {
		return &types.Interruption{}
	}
	return nil
}
func (tx *engineTx) WriteRequestBody(body []byte) (*types.Interruption, int, error) {
	tx.note("write:" + string(body))
	n := len(body)
	if tx.shortWrite {
		n--
	}
	return nil, n, nil
}
func (tx *engineTx) ProcessRequestBody() (*types.Interruption, error) {
	tx.note("body")
	tx.phase.wait()
	tx.last = types.PhaseRequestBody
	if tx.bodyError {
		return nil, errors.New("fixed synthetic phase error")
	}
	return nil, nil
}
func (tx *engineTx) ProcessLogging() { tx.logCalls.Add(1); tx.note("log"); tx.logging.wait() }
func (tx *engineTx) Close() error {
	tx.closeCalls.Add(1)
	tx.note("close")
	tx.closed.Store(true) // Simulated pool-return boundary, not real Coraza.
	tx.closing.wait()
	return tx.closeError
}
func (tx *engineTx) releaseAll() {
	tx.headers.open()
	tx.phase.open()
	tx.logging.open()
	tx.closing.open()
}

type engineFactory struct {
	mu                     sync.Mutex
	transactions           []*engineTx
	creating, retiring     *engineGate
	calls, closes          atomic.Int32
	nilResult, panicCreate bool
}

func newEngineFactory(t *testing.T, txs ...*engineTx) *engineFactory {
	return &engineFactory{transactions: txs, creating: newEngineGate(t, false), retiring: newEngineGate(t, false)}
}
func (f *engineFactory) NewTransactionWithID(string) types.Transaction {
	f.calls.Add(1)
	f.creating.wait()
	if f.panicCreate {
		panic("fixed synthetic factory panic")
	}
	if f.nilResult {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	tx := f.transactions[0]
	f.transactions = f.transactions[1:]
	return tx
}
func (f *engineFactory) Close() error { f.closes.Add(1); f.retiring.wait(); return nil }

type engineSource struct {
	io.Reader
	closing    *engineGate
	closeError error
}

func (s *engineSource) Close() error { s.closing.wait(); return s.closeError }

func engineFixture(t *testing.T, f *engineFactory) (*Owner, *Generation, context.Context, context.CancelFunc) {
	t.Helper()
	o, err := newEngineOwner(f, f)
	if err != nil {
		t.Fatal(err)
	}
	g, err := o.NewGeneration(engineTestGeneration)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*engineTestBound)
	t.Cleanup(cancel)
	t.Cleanup(func() {
		f.creating.open()
		f.retiring.open()
		o.state.mu.Lock()
		retired := g.state.retired
		o.state.mu.Unlock()
		// All later-registered job cleanups have joined by this point. An
		// idempotent Retire synchronously completes the scheduling decision;
		// j.done alone precedes that decision in finishInspection.
		if retired {
			g.Retire()
		}
		o.state.mu.Lock()
		started := o.state.engine.cacheCloseStarted
		o.state.mu.Unlock()
		if started {
			engineReached(t, o.state.engine.cacheDone)
		}
	})
	return o, g, ctx, cancel
}
func engineMetadata() engineInput {
	return engineInput{id: "Synthetic_1", sni: "app.test", protocol: "HTTP/1.1", method: "POST", target: "/a%2Fb?q=one", client: netip.MustParseAddrPort("192.0.2.1:1234"), server: netip.MustParseAddrPort("192.0.2.2:8443"), publicPort: 443, fields: []requestctx.Field{{Name: "Host", Value: "app.test"}, {Name: "Content-Type", Value: "application/json"}, {Name: "Content-Length", Value: "2"}}}
}
func engineBegin(t *testing.T, o *Owner, g *Generation, ctx context.Context, f *engineFactory, tx *engineTx, source *engineSource) (*Job, *Inbound) {
	t.Helper()
	in, err := o.ReserveInbound()
	if err != nil {
		t.Fatal(err)
	}
	j, err := g.beginInspection(ctx, in, source, 2, engineMetadata())
	if err != nil {
		_ = in.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		f.creating.open()
		f.retiring.open()
		source.closing.open()
		if tx != nil {
			tx.releaseAll()
		}
		wait, cancel := context.WithTimeout(context.Background(), engineTestBound)
		defer cancel()
		if out, err := j.Wait(wait); err != nil || !out.Joined {
			t.Errorf("owned fake worker did not join: %v", err)
		}
		if tx != nil && tx.trace.postClose.Load() != 0 {
			t.Error("engine object used after Close")
		}
	})
	return j, in
}
func engineBody(t *testing.T) *engineSource {
	return &engineSource{Reader: strings.NewReader("{}"), closing: newEngineGate(t, false)}
}
func engineJoin(t *testing.T, j *Job) Outcome {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), engineTestBound)
	defer cancel()
	out, err := j.Wait(ctx)
	if err != nil || !out.Joined {
		t.Fatal("expected fake job join", err)
	}
	if out.Recorded || out.Engine.InspectionComplete || out.Record.Generation != "" || len(out.Record.Body) != 0 {
		t.Fatal("engine lifecycle minted positive output")
	}
	return out
}
func engineUsage(t *testing.T, o *Owner, r, s int) {
	t.Helper()
	u := o.Usage()
	if u.Requests != r || u.Sockets != s {
		t.Fatalf("charges=%+v want (%d,%d)", u, r, s)
	}
}

func TestEngineContinuousLeaseAndExactMapping(t *testing.T) {
	tx := newEngineTx(t, true, true)
	f := newEngineFactory(t, tx)
	o, g, ctx, _ := engineFixture(t, f)
	source := engineBody(t)
	source.closing = newEngineGate(t, true)
	j, in := engineBegin(t, o, g, ctx, f, tx, source)
	engineReached(t, source.closing.entered)
	engineUsage(t, o, 1, 2)
	if f.calls.Load() != 0 || !errors.Is(in.Close(), ErrTransferred) {
		t.Fatal("body/engine gap or inbound refund")
	}
	source.closing.open()
	engineReached(t, tx.phase.entered)
	engineUsage(t, o, 1, 2)
	if f.calls.Load() != 1 || tx.logCalls.Load() != 0 || tx.closeCalls.Load() != 0 {
		t.Fatal("phase overlapped cleanup")
	}
	tx.phase.open()
	engineReached(t, tx.closing.entered)
	engineUsage(t, o, 1, 2)
	if tx.logCalls.Load() != 1 || tx.closeCalls.Load() != 1 {
		t.Fatal("serial cleanup counts")
	}
	tx.closing.open()
	out := engineJoin(t, j)
	engineUsage(t, o, 0, 0)
	if !out.Engine.CleanupCertain || !out.Engine.Released || !out.Engine.WorkersDone || out.Engine.Fault != EngineNone {
		t.Fatal("clean lifecycle incomplete", out.Engine)
	}
	rows := tx.trace.rows()
	prefix := []string{"variables", "connection:192.0.2.1:1234:192.0.2.2:8443", "uri:/a%2Fb?q=one:POST:HTTP/1.1", "sni:app.test", "header:Host:app.test", "header:Content-Type:application/json", "header:Content-Length:2", "off", "access", "headers"}
	if len(rows) < len(prefix) || !reflect.DeepEqual(rows[:len(prefix)], prefix) {
		t.Fatal("request mapping/order differs")
	}
	for _, want := range []string{"get:inbound", "get:body", "get:processor", "get:urlencoded", "get:arguments", "get:uri"} {
		count := 0
		for _, got := range rows {
			if got == want {
				count++
			}
		}
		if count != 2 {
			t.Fatal("missing phase/error-variable check")
		}
	}
	if rows[len(rows)-2] != "log" || rows[len(rows)-1] != "close" {
		t.Fatal("cleanup not final serial operations")
	}
}

func TestEngineCancellationKeepsActiveTransactionCharged(t *testing.T) {
	tx := newEngineTx(t, true, false)
	f := newEngineFactory(t, tx)
	o, g, ctx, cancel := engineFixture(t, f)
	j, _ := engineBegin(t, o, g, ctx, f, tx, engineBody(t))
	engineReached(t, tx.phase.entered)
	cancel()
	observer, stop := context.WithCancel(context.Background())
	stop()
	if out, err := j.Wait(observer); !errors.Is(err, context.Canceled) || out.Joined {
		t.Fatal("blocked phase fabricated join")
	}
	engineUsage(t, o, 1, 2)
	if tx.closeCalls.Load() != 0 {
		t.Fatal("Close raced active phase")
	}
	tx.phase.open()
	out := engineJoin(t, j)
	engineUsage(t, o, 0, 0)
	if !out.Canceled || tx.logCalls.Load() != 1 || tx.closeCalls.Load() != 1 {
		t.Fatal("cancel skipped serial cleanup")
	}
}

func TestEngineOrdinaryFailuresCloseWithoutSuccess(t *testing.T) {
	for _, kind := range []string{"headers", "body", "short", "processor", "uri", "off", "access", "nilvars"} {
		t.Run(kind, func(t *testing.T) {
			tx := newEngineTx(t, false, false)
			switch kind {
			case "headers":
				tx.headerReject = true
			case "body":
				tx.bodyError = true
			case "short":
				tx.shortWrite = true
			case "processor", "uri":
				tx.vars.bad = kind
			case "off":
				tx.off = true
			case "access":
				tx.inaccessible = true
			case "nilvars":
				tx.nilVars = true
			}
			f := newEngineFactory(t, tx)
			o, g, ctx, _ := engineFixture(t, f)
			j, _ := engineBegin(t, o, g, ctx, f, tx, engineBody(t))
			out := engineJoin(t, j)
			engineUsage(t, o, 0, 0)
			wantLog := int32(1)
			if kind == "off" || kind == "access" || kind == "nilvars" {
				wantLog = 0
			}
			if out.Engine.Fault == EngineNone || tx.closeCalls.Load() != 1 || tx.logCalls.Load() != wantLog {
				t.Fatal("ordinary failure disposition", out.Engine)
			}
		})
	}
}

func TestEngineBusyFactoryAndCloseErrorPoison(t *testing.T) {
	tx := newEngineTx(t, false, true)
	tx.closeError = errors.New("fixed synthetic Close error")
	f := newEngineFactory(t, tx)
	o, g, ctx, _ := engineFixture(t, f)
	j, _ := engineBegin(t, o, g, ctx, f, tx, engineBody(t))
	engineReached(t, tx.closing.entered)
	second, _ := engineBegin(t, o, g, ctx, f, nil, engineBody(t))
	out := engineJoin(t, second)
	if out.Engine.Fault != EngineBusy || f.calls.Load() != 1 {
		t.Fatal("busy Close allowed another creation")
	}
	engineUsage(t, o, 1, 2)
	tx.closing.open()
	out = engineJoin(t, j)
	if out.Engine.Fault != EngineClose || !out.Engine.Uncertain || out.Engine.Released || !out.Engine.CloseReturned {
		t.Fatal("Close error lost ownership")
	}
	engineUsage(t, o, 1, 2)
	if _, err := o.ReserveInbound(); !errors.Is(err, ErrStopped) || f.calls.Load() != 1 || tx.closeCalls.Load() != 1 {
		t.Fatal("poisoned owner reopened")
	}
}

func TestEngineFactoryBusyIsImmediateAndOwnsOnlyFirstJob(t *testing.T) {
	tx := newEngineTx(t, false, false)
	f := newEngineFactory(t, tx)
	f.creating = newEngineGate(t, true)
	o, g, ctx, _ := engineFixture(t, f)
	j, _ := engineBegin(t, o, g, ctx, f, tx, engineBody(t))
	engineReached(t, f.creating.entered)
	second, _ := engineBegin(t, o, g, ctx, f, nil, engineBody(t))
	out := engineJoin(t, second)
	if out.Engine.Fault != EngineBusy || f.calls.Load() != 1 {
		t.Fatal("creation queued/reissued")
	}
	engineUsage(t, o, 1, 2)
	f.creating.open()
	engineJoin(t, j)
	engineUsage(t, o, 0, 0)
}

func TestEngineBodyCloseErrorNeverCreatesTransaction(t *testing.T) {
	tx := newEngineTx(t, false, false)
	f := newEngineFactory(t, tx)
	o, g, ctx, _ := engineFixture(t, f)
	source := engineBody(t)
	source.closeError = errors.New("fixed synthetic body Close error")
	j, _ := engineBegin(t, o, g, ctx, f, tx, source)
	out := engineJoin(t, j)
	if f.calls.Load() != 0 || tx.logCalls.Load() != 0 || tx.closeCalls.Load() != 0 || !out.Engine.Uncertain || out.Engine.Released {
		t.Fatal("uncertain body created engine/refunded")
	}
	engineUsage(t, o, 1, 2)
}

func TestEnginePanicsAndNilRetainUncertainty(t *testing.T) {
	for _, stage := range []string{"nil", "factory", "headers", "body", "log", "close", "variables"} {
		t.Run(stage, func(t *testing.T) {
			tx := newEngineTx(t, false, false)
			f := newEngineFactory(t, tx)
			if stage == "nil" {
				f.nilResult = true
			} else if stage == "factory" {
				f.panicCreate = true
			} else {
				tx.panicAt = stage
			}
			o, g, ctx, _ := engineFixture(t, f)
			j, _ := engineBegin(t, o, g, ctx, f, tx, engineBody(t))
			out := engineJoin(t, j)
			if out.Engine.Fault != EngineUnsafe || !out.Engine.Uncertain || out.Engine.Released || f.closes.Load() != 0 {
				t.Fatal("Unsafe disposition differs", out.Engine)
			}
			wantLog, wantClose := int32(0), int32(0)
			if stage == "log" || stage == "close" {
				wantLog = 1
			}
			if stage == "close" {
				wantClose = 1
			}
			if f.calls.Load() != 1 || tx.logCalls.Load() != wantLog || tx.closeCalls.Load() != wantClose {
				t.Fatal("Unsafe stage call counts differ")
			}
			rows := tx.trace.rows()
			if stage == "nil" || stage == "factory" {
				if len(rows) != 0 {
					t.Fatal("API called after unknown factory result")
				}
			} else if len(rows) == 0 || rows[len(rows)-1] != stage {
				t.Fatal("intended panic stage not reached, or later API started")
			}
			engineUsage(t, o, 1, 2)
			if _, err := o.ReserveInbound(); !errors.Is(err, ErrStopped) {
				t.Fatal("Unsafe owner admitted")
			}
		})
	}
}

func TestEngineRetireAfterFactoryBeforePhaseAndCacheOnlyClose(t *testing.T) {
	tx := newEngineTx(t, false, false)
	f := newEngineFactory(t, tx)
	f.creating = newEngineGate(t, true)
	f.retiring = newEngineGate(t, true)
	o, g, ctx, _ := engineFixture(t, f)
	j, _ := engineBegin(t, o, g, ctx, f, tx, engineBody(t))
	engineReached(t, f.creating.entered)
	g.Retire()
	if f.closes.Load() != 0 {
		t.Fatal("WAF closed under active creation")
	}
	engineUsage(t, o, 1, 2)
	if _, err := o.NewGeneration(engineTestGeneration); !errors.Is(err, ErrRetired) {
		t.Fatal("second generation admitted")
	}
	f.creating.open()
	out := engineJoin(t, j)
	engineReached(t, f.retiring.entered)
	t.Cleanup(func() { f.retiring.open(); engineReached(t, o.state.engine.cacheDone) })
	if tx.logCalls.Load() != 0 || tx.closeCalls.Load() != 1 || out.Engine.PhasesReturned || f.closes.Load() != 1 {
		t.Fatal("retirement ordering differs")
	}
	engineUsage(t, o, 0, 0)
	f.retiring.open()
	engineReached(t, o.state.engine.cacheDone)
	o.state.mu.Lock()
	cacheReleased := o.state.engine.cacheReleased
	o.state.mu.Unlock()
	if !cacheReleased {
		t.Fatal("cache release marker absent")
	}
	if _, err := o.NewGeneration(engineTestGeneration); !errors.Is(err, ErrRetired) {
		t.Fatal("cache release reset generation")
	}
}

func TestEngineStopSuppressesCleanupLoggingButClosesKnownTransaction(t *testing.T) {
	tx := newEngineTx(t, true, false)
	f := newEngineFactory(t, tx)
	o, g, ctx, _ := engineFixture(t, f)
	j, _ := engineBegin(t, o, g, ctx, f, tx, engineBody(t))
	engineReached(t, tx.phase.entered)
	o.Stop()
	tx.phase.open()
	out := engineJoin(t, j)
	engineUsage(t, o, 0, 0)
	if tx.logCalls.Load() != 0 || tx.closeCalls.Load() != 1 || !out.Stopped {
		t.Fatal("stop cleanup exception differs")
	}
}

func TestEngineRetireBeforeFactoryAndAfterMetadataSkipsLogging(t *testing.T) {
	for _, at := range []string{"body", "metadata"} {
		t.Run(at, func(t *testing.T) {
			tx := newEngineTx(t, false, false)
			f := newEngineFactory(t, tx)
			o, g, ctx, _ := engineFixture(t, f)
			source := engineBody(t)
			if at == "body" {
				source.closing = newEngineGate(t, true)
			} else {
				tx.hook = func(value string) {
					if value == "sni:app.test" {
						g.Retire()
					}
				}
			}
			j, _ := engineBegin(t, o, g, ctx, f, tx, source)
			if at == "body" {
				engineReached(t, source.closing.entered)
				g.Retire()
				source.closing.open()
			}
			out := engineJoin(t, j)
			if !out.Retired || out.Engine.PhasesReturned || tx.logCalls.Load() != 0 {
				t.Fatal("metadata/retirement manufactured logging eligibility")
			}
			want := int32(1)
			if at == "body" {
				want = 0
			}
			if f.calls.Load() != want || tx.closeCalls.Load() != want {
				t.Fatal("retirement factory/Close counts differ")
			}
			engineUsage(t, o, 0, 0)
		})
	}
}
