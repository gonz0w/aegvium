// SPDX-License-Identifier: BSD-3-Clause
package bodyowner

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

func TestPolicyStartupIsOneAttemptAcrossCopies(t *testing.T) {
	p := newPolicyStartup()
	copyP := p
	f := newEngineFactory(t)
	calls := 0
	build := func() (policyConstruction, error) {
		calls++
		return policyConstruction{factory: f, closer: f, rules: 42}, nil
	}
	o, err := p.construct(build)
	if err != nil || o == nil || o.state.engine.policy == nil || o.state.engine.policy.ruleCount != 42 {
		t.Fatal("private preparation failed")
	}
	if second, err := copyP.construct(build); second != nil || !errors.Is(err, ErrStopped) || calls != 1 {
		t.Fatal("copied guard reconstructed an engine")
	}
	if f.calls.Load() != 0 || f.closes.Load() != 0 || p.state.held.factory != nil || p.state.held.closer != nil {
		t.Fatal("construction executed engine or retained owner alias")
	}
}

func TestPolicyStartupFailureConsumesAndRetains(t *testing.T) {
	for _, kind := range []string{"error", "factory", "closer", "zero", "negative", "above"} {
		t.Run(kind, func(t *testing.T) {
			p := newPolicyStartup()
			f := newEngineFactory(t)
			calls := 0
			result := policyConstruction{factory: f, closer: f, rules: 42}
			var buildErr error
			switch kind {
			case "error":
				buildErr = errors.New("fixed synthetic construction error")
			case "factory":
				result.factory = nil
			case "closer":
				result.closer = nil
			case "zero":
				result.rules = 0
			case "negative":
				result.rules = -1
			case "above":
				result.rules = 65536
			}
			build := func() (policyConstruction, error) { calls++; return result, buildErr }
			if o, err := p.construct(build); o != nil || err != errPolicyPreparation {
				t.Fatal("failed preparation returned owner/error text")
			}
			if o, err := p.construct(build); o != nil || err != ErrStopped || calls != 1 {
				t.Fatal("failed attempt retried")
			}
			if p.state.held.factory != result.factory || p.state.held.closer != result.closer || f.closes.Load() != 0 {
				t.Fatal("known partial engine was dropped/closed")
			}
		})
	}
	// The numeric bound is diagnostic admission only, not resource acceptance.
	p := newPolicyStartup()
	f := newEngineFactory(t)
	if o, err := p.construct(func() (policyConstruction, error) {
		return policyConstruction{factory: f, closer: f, rules: 65535}, nil
	}); err != nil || o.state.engine.policy.ruleCount != 65535 {
		t.Fatal("literal diagnostic boundary changed")
	}
}

func TestPolicyStartupPanicConsumesKnownAndUnknownAcquisition(t *testing.T) {
	for _, known := range []bool{false, true} {
		t.Run(map[bool]string{false: "unknown", true: "known"}[known], func(t *testing.T) {
			p := newPolicyStartup()
			f := newEngineFactory(t)
			calls := 0
			build := func() (policyConstruction, error) {
				calls++
				if known {
					p.hold(policyConstruction{factory: f, closer: f})
				}
				panic("fixed synthetic constructor panic")
			}
			if o, err := p.construct(build); o != nil || err != errPolicyPreparation {
				t.Fatal("panic escaped fixed startup failure")
			}
			if o, err := p.construct(build); o != nil || err != ErrStopped || calls != 1 || f.closes.Load() != 0 {
				t.Fatal("panic allowed retry/speculative close")
			}
			if known && (p.state.held.factory != f || p.state.held.closer != f) {
				t.Fatal("known partial lost after panic")
			}
		})
	}
}

func TestPolicyBlockedConstructorRejectsSecondAndJoinsBoth(t *testing.T) {
	p := newPolicyStartup()
	f := newEngineFactory(t)
	gate := newEngineGate(t, true)
	var calls atomic.Int32
	build := func() (policyConstruction, error) {
		calls.Add(1)
		gate.wait()
		return policyConstruction{factory: f, closer: f, rules: 42}, nil
	}
	type result struct {
		owner *Owner
		err   error
	}
	first, second := make(chan result, 1), make(chan result, 1)
	firstJoined, secondJoined := false, false
	secondStarted := false
	t.Cleanup(func() {
		gate.open()
		for _, entry := range []struct {
			started bool
			joined  *bool
			results <-chan result
		}{{true, &firstJoined, first}, {secondStarted, &secondJoined, second}} {
			if entry.started && !*entry.joined {
				select {
				case <-entry.results:
					*entry.joined = true
				case <-time.After(engineTestBound):
					t.Error("finite constructor caller did not join")
				}
			}
		}
	})
	go func() { o, err := p.construct(build); first <- result{o, err} }()
	engineReached(t, gate.entered)
	secondStarted = true
	go func() { copyP := p; o, err := copyP.construct(build); second <- result{o, err} }()
	select {
	case got := <-second:
		secondJoined = true
		if got.owner != nil || got.err != ErrStopped {
			t.Fatal("blocked construction queued second caller")
		}
	case <-time.After(engineTestBound):
		t.Fatal("second constructor did not refuse immediately")
	}
	if calls.Load() != 1 {
		t.Fatal("multiple builder commitments")
	}
	gate.open()
	select {
	case got := <-first:
		firstJoined = true
		if got.owner == nil || got.err != nil {
			t.Fatal("first construction failed after release")
		}
	case <-time.After(engineTestBound):
		t.Fatal("first caller did not return")
	}
}

type policyFormatterTrap struct{ plugintypes.AuditLogFormatter }

func TestPolicyWriterNeverInspectsPayloadConfigOrFormatter(t *testing.T) {
	w := noOutputAuditWriter{}
	// Embedded nil API methods panic if the writer tries to format/read content.
	cfg := plugintypes.AuditLogConfig{Target: "not-opened", Dir: "not-created", Formatter: policyFormatterTrap{}}
	if w.Init(cfg) != nil || w.Write(nil) != nil || w.Close() != nil || w.Write(struct{ plugintypes.AuditLog }{}) != nil {
		t.Fatal("no-output writer failed")
	}
	if reflect.TypeOf(w).NumField() != 0 {
		t.Fatal("writer acquired retained storage")
	}
}

func TestPolicyLiteralDirectivesAndSourcePin(t *testing.T) {
	const expected = `Include @coraza.conf-recommended
Include @crs-setup.conf.example
Include @owasp_crs/*.conf
SecRuleEngine On
SecRequestBodyAccess On
SecRequestBodyLimit 4097
SecRequestBodyInMemoryLimit 4097
SecRequestBodyLimitAction Reject
SecResponseBodyAccess Off
SecAuditEngine Off
SecAuditLogType aegvium_no_output_v1
SecDebugLogLevel 0
`
	// Independent reviewer hashed decoded binding238 + directives324 bytes,
	// including both terminal LFs, before any Go/policy execution.
	const expectedPin = "60bd9c673606ad0f314bb11f58eca4e981872f1f7123f3cb0e8fade8bd77943c"
	if policyDirectives != expected || policyWriterName != "aegvium_no_output_v1" || policyPin() != expectedPin {
		t.Fatal("fixed policy order/source identity differs")
	}
}

func TestPolicyPreparedOwnerDiagnosticAndPinBinding(t *testing.T) {
	tx := newEngineTx(t, false, false)
	f := newEngineFactory(t, tx)
	p := newPolicyStartup()
	o, err := p.construct(func() (policyConstruction, error) { return policyConstruction{factory: f, closer: f, rules: 42}, nil })
	if err != nil {
		t.Fatal(err)
	}
	g, err := o.NewGeneration(engineTestGeneration)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*engineTestBound)
	t.Cleanup(cancel)
	for _, pin := range []string{"", strings.Repeat("0", 64), strings.Repeat("A", 64), strings.Repeat("0", 65)} {
		in, err := o.ReserveInbound()
		if err != nil {
			t.Fatal(err)
		}
		input := engineMetadata()
		input.policyPin = pin
		source := engineBody(t)
		if j, err := g.beginInspection(ctx, in, source, 2, input); j != nil || err != ErrInput || f.calls.Load() != 0 {
			t.Fatal("wrong policy pin transferred source/started engine")
		}
		if signaled(source.closing.entered) {
			t.Fatal("wrong pin closed caller-owned source")
		}
		if source.Close() != nil {
			t.Fatal("caller source cleanup failed")
		}
		if err := in.Close(); err != nil {
			t.Fatal("wrong pin consumed inbound")
		}
		engineUsage(t, o, 0, 0)
	}
	in, err := o.ReserveInbound()
	if err != nil {
		t.Fatal(err)
	}
	input := engineMetadata()
	input.policyPin = policyPin()
	source := engineBody(t)
	j, err := g.beginInspection(ctx, in, source, 2, input)
	if err != nil {
		_ = in.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		tx.releaseAll()
		source.closing.open()
		f.creating.open()
		f.retiring.open()
		wait, cancel := context.WithTimeout(context.Background(), engineTestBound)
		defer cancel()
		if out, err := j.Wait(wait); err != nil || !out.Joined {
			t.Errorf("prepared fake job did not join: %v", err)
		}
	})
	out := engineJoin(t, j)
	engineUsage(t, o, 0, 0)
	if out.Engine.RequestID != "Synthetic_1" || out.Engine.Generation != engineTestGeneration || out.Engine.PolicyPin != policyPin() || out.Engine.RuleCount != 42 || out.Engine.IntendedMode != "OnUnqualified" || out.Engine.BackendEffect != "NoBackendAttempt" || out.Engine.Fault != EngineNone || tx.trace.postClose.Load() != 0 {
		t.Fatal("bounded diagnostics/source binding differs")
	}
}
