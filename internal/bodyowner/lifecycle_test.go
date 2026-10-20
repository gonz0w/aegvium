// SPDX-License-Identifier: BSD-3-Clause
package bodyowner_test

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gonz0w/aegvium/internal/bodyowner"
)

const lifeGeneration = "00000000000000000000000000000000"
const lifeBound = 2 * time.Second

// Every gate is releasable independently of cancellation or the implementation.
// Cleanup releases both before waiting, including after an assertion fails.
type lifeSource struct {
	readEntered, closeEntered chan struct{}
	readRelease, closeRelease chan struct{}
	readSignal, closeSignal   sync.Once
	readFree, closeFree       sync.Once
	reads, closes             atomic.Int32
	data                      string
	readError, closeError     error
}

func newLifeSource(t *testing.T, holdRead, holdClose bool, data string, readErr, closeErr error) *lifeSource {
	t.Helper()
	s := &lifeSource{
		readEntered: make(chan struct{}), closeEntered: make(chan struct{}),
		readRelease: make(chan struct{}), closeRelease: make(chan struct{}),
		data: data, readError: readErr, closeError: closeErr,
	}
	if !holdRead {
		s.releaseRead()
	}
	if !holdClose {
		s.releaseClose()
	}
	t.Cleanup(s.releaseAll)
	return s
}

func (s *lifeSource) Read(p []byte) (int, error) {
	call := s.reads.Add(1)
	s.readSignal.Do(func() { close(s.readEntered) })
	<-s.readRelease
	if call > 1 {
		return 0, io.EOF
	}
	return copy(p, s.data), s.readError
}

func (s *lifeSource) Close() error {
	s.closes.Add(1)
	s.closeSignal.Do(func() { close(s.closeEntered) })
	<-s.closeRelease
	return s.closeError
}

func (s *lifeSource) releaseRead()  { s.readFree.Do(func() { close(s.readRelease) }) }
func (s *lifeSource) releaseClose() { s.closeFree.Do(func() { close(s.closeRelease) }) }
func (s *lifeSource) releaseAll()   { s.releaseRead(); s.releaseClose() }

func lifeFixture(t *testing.T) (*bodyowner.Owner, *bodyowner.Generation, context.Context, context.CancelFunc) {
	t.Helper()
	o := bodyowner.New()
	g, err := o.NewGeneration(lifeGeneration)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*lifeBound)
	t.Cleanup(cancel)
	return o, g, ctx, cancel
}

func lifeInbound(t *testing.T, o *bodyowner.Owner) *bodyowner.Inbound {
	t.Helper()
	in, err := o.ReserveInbound()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = in.Close() })
	return in
}

func lifeTrack(t *testing.T, j *bodyowner.Job, s *lifeSource) {
	t.Helper()
	t.Cleanup(func() {
		s.releaseAll()
		ctx, cancel := context.WithTimeout(context.Background(), lifeBound)
		defer cancel()
		out, err := j.Wait(ctx)
		if err != nil || !out.Joined {
			t.Errorf("finite fixture did not join during cleanup: joined=%v err=%v", out.Joined, err)
		}
	})
}

func lifeBegin(t *testing.T, g *bodyowner.Generation, ctx context.Context, in *bodyowner.Inbound, s *lifeSource, length int) *bodyowner.Job {
	t.Helper()
	j, err := g.Begin(ctx, in, s, length)
	if err != nil || j == nil {
		t.Fatal("expected admitted job", err)
	}
	lifeTrack(t, j, s)
	return j
}

func lifeEntered(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(lifeBound):
		t.Fatal("finite fixture did not reach its barrier")
	}
}

func lifeJoined(t *testing.T, j *bodyowner.Job) bodyowner.Outcome {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), lifeBound)
	defer cancel()
	out, err := j.Wait(ctx)
	if err != nil || !out.Joined {
		t.Fatal("expected completed ownership protocol", err)
	}
	return out
}

func lifePending(t *testing.T, j *bodyowner.Job) bodyowner.Outcome {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	out, err := j.Wait(ctx)
	if !errors.Is(err, context.Canceled) || out.Joined || out.Recorded || out.Record.Generation != "" || len(out.Record.Body) != 0 {
		t.Fatalf("observer did not report pending ownership without bytes: %+v err=%v", out, err)
	}
	return out
}

func lifeUsage(t *testing.T, o *bodyowner.Owner, requests, sockets int) {
	t.Helper()
	got := o.Usage()
	if got.Requests != requests || got.Sockets != sockets {
		t.Fatalf("usage got %+v; want requests=%d sockets=%d", got, requests, sockets)
	}
}

func lifeCounts(t *testing.T, s *lifeSource, reads, closes int32) {
	t.Helper()
	if s.reads.Load() != reads || s.closes.Load() != closes {
		t.Fatalf("I/O counts got read=%d close=%d; want read=%d close=%d", s.reads.Load(), s.closes.Load(), reads, closes)
	}
}

func TestCancellationRetainsChargeUntilReadAndCloseJoin(t *testing.T) {
	o, g, ctx, cancel := lifeFixture(t)
	in := lifeInbound(t, o)
	inCopy := *in
	s := newLifeSource(t, true, false, "A", io.EOF, nil)
	j := lifeBegin(t, g, ctx, in, s, 1)
	lifeEntered(t, s.readEntered)
	cancel()
	lifeEntered(t, s.closeEntered)
	out := lifePending(t, j)
	if !out.Canceled || out.CloseFailed {
		t.Fatal("cancellation or Close state lost", out)
	}
	if err := inCopy.Close(); !errors.Is(err, bodyowner.ErrTransferred) {
		t.Fatal("copied inbound refunded pending I/O", err)
	}
	lifeUsage(t, o, 1, 2)
	s.releaseRead()
	out = lifeJoined(t, j)
	if !out.Canceled || out.Recorded || out.ReadFailure != bodyowner.None {
		t.Fatal("late Read revived recording or lost cancellation", out)
	}
	lifeUsage(t, o, 0, 0)
	lifeCounts(t, s, 1, 1)
	if err := inCopy.Close(); err != nil {
		t.Fatal(err)
	}
	lifeUsage(t, o, 0, 0)
}

func TestObserverCancellationCopiesAndFrozenDetachedRecord(t *testing.T) {
	o, g, ctx, _ := lifeFixture(t)
	s := newLifeSource(t, false, true, "AB", io.EOF, nil)
	j := lifeBegin(t, g, ctx, lifeInbound(t, o), s, 2)
	copyJob := *j
	lifeEntered(t, s.closeEntered)
	out := lifePending(t, &copyJob)
	if out.Canceled || out.Retired || out.Stopped {
		t.Fatal("observer canceled the capture", out)
	}
	lifeUsage(t, o, 1, 2)
	if zero, err := j.Wait(nil); !errors.Is(err, bodyowner.ErrInput) || zero.Joined || zero.Recorded {
		t.Fatal("nil observer was accepted", err)
	}
	s.releaseClose()
	out = lifeJoined(t, &copyJob)
	if !out.Recorded || out.Record.Generation != lifeGeneration || string(out.Record.Body) != "AB" {
		t.Fatal("clean body was not recorded", out)
	}
	out.Record.Body[0] = 'Z'
	if got := j.Outcome(); string(got.Record.Body) != "AB" {
		t.Fatal("Outcome exposed owned backing memory")
	}
	ctxCanceled, cancel := context.WithCancel(context.Background())
	cancel()
	completed, err := j.Wait(ctxCanceled)
	if err != nil || !completed.Joined || !completed.Recorded || string(completed.Record.Body) != "AB" {
		t.Fatal("ready completion did not win over canceled observer", err)
	}
	completed.Record.Body[1] = 'Z'
	g.Retire()
	o.Stop()
	frozen := j.Outcome()
	if !frozen.Recorded || frozen.Canceled || frozen.Retired || frozen.Stopped || string(frozen.Record.Body) != "AB" {
		t.Fatal("later lifecycle events changed historical outcome", frozen)
	}
	lifeUsage(t, o, 0, 0)
	lifeCounts(t, s, 1, 1)
}

func TestCopiedGenerationRetirementDuringCloseSuppressesRecord(t *testing.T) {
	o, g, ctx, _ := lifeFixture(t)
	copyGeneration := *g
	s := newLifeSource(t, false, true, "A", io.EOF, nil)
	j := lifeBegin(t, g, ctx, lifeInbound(t, o), s, 1)
	lifeEntered(t, s.closeEntered)
	copyGeneration.Retire()
	if out := lifePending(t, j); !out.Retired || !out.Canceled {
		t.Fatal("copied retirement did not reach active job", out)
	}
	lifeUsage(t, o, 1, 2)
	free := lifeInbound(t, o)
	refused := newLifeSource(t, false, false, "", io.EOF, nil)
	if extra, err := g.Begin(ctx, free, refused, 0); extra != nil || !errors.Is(err, bodyowner.ErrRetired) {
		t.Fatal("generation copy left original admitting", err)
	}
	lifeCounts(t, refused, 0, 0)
	if err := free.Close(); err != nil {
		t.Fatal(err)
	}
	other, err := o.NewGeneration("11111111111111111111111111111111")
	if err != nil {
		t.Fatal(err)
	}
	otherSource := newLifeSource(t, false, false, "B", io.EOF, nil)
	otherJob := lifeBegin(t, other, ctx, lifeInbound(t, o), otherSource, 1)
	if out := lifeJoined(t, otherJob); !out.Recorded {
		t.Fatal("retiring one generation stopped another", out)
	}
	lifeUsage(t, o, 1, 2)
	s.releaseClose()
	if out := lifeJoined(t, j); out.Recorded || !out.Retired || !out.Canceled {
		t.Fatal("retired job published after successful Close", out)
	}
	lifeUsage(t, o, 0, 0)
}

func TestCopiedOwnerStopPreservesCallerFreeReservation(t *testing.T) {
	o, g, ctx, _ := lifeFixture(t)
	copyOwner := *o
	free := lifeInbound(t, o)
	s := newLifeSource(t, true, false, "A", io.EOF, nil)
	j := lifeBegin(t, g, ctx, lifeInbound(t, o), s, 1)
	lifeEntered(t, s.readEntered)
	copyOwner.Stop()
	lifeEntered(t, s.closeEntered)
	if out := lifePending(t, j); !out.Stopped || !out.Canceled {
		t.Fatal("copied owner Stop missed active job", out)
	}
	lifeUsage(t, o, 1, 3)
	if in, err := o.ReserveInbound(); in != nil || !errors.Is(err, bodyowner.ErrStopped) {
		t.Fatal("original owner remained admitting", err)
	}
	if generation, err := copyOwner.NewGeneration(lifeGeneration); generation != nil || !errors.Is(err, bodyowner.ErrStopped) {
		t.Fatal("stopped alias constructed a generation", err)
	}
	if err := free.Close(); err != nil {
		t.Fatal("Stop stole caller-owned free inbound", err)
	}
	lifeUsage(t, o, 1, 2)
	s.releaseRead()
	if out := lifeJoined(t, j); out.Recorded || !out.Stopped || !out.Canceled {
		t.Fatal("stopped job recorded", out)
	}
	lifeUsage(t, o, 0, 0)
}

func TestCloseErrorPoisonsOwnerBeforeBlockedReadJoins(t *testing.T) {
	o, g, ctx, _ := lifeFixture(t)
	peer := newLifeSource(t, true, false, "B", io.EOF, nil)
	peerJob := lifeBegin(t, g, ctx, lifeInbound(t, o), peer, 1)
	lifeEntered(t, peer.readEntered)
	badContext, cancelBad := context.WithCancel(ctx)
	t.Cleanup(cancelBad)
	bad := newLifeSource(t, true, false, "A", io.EOF, errors.New("synthetic close failure"))
	badInbound := lifeInbound(t, o)
	badJob := lifeBegin(t, g, badContext, badInbound, bad, 1)
	lifeEntered(t, bad.readEntered)
	cancelBad()
	// The other job's Close proves poison was delivered while bad.Read is held.
	lifeEntered(t, peer.closeEntered)
	out := lifePending(t, badJob)
	if !out.CloseFailed || !out.Stopped || !out.Canceled {
		t.Fatal("Close error was deferred until Read joined", out)
	}
	lifeUsage(t, o, 2, 4)
	if in, err := o.ReserveInbound(); in != nil || !errors.Is(err, bodyowner.ErrStopped) {
		t.Fatal("poisoned owner admitted", err)
	}
	bad.releaseRead()
	out = lifeJoined(t, badJob)
	if !out.CloseFailed || !out.Stopped || !out.Canceled || out.Recorded {
		t.Fatal("joined Close failure was mislabeled clean", out)
	}
	lifeUsage(t, o, 2, 4)
	peer.releaseRead()
	if out := lifeJoined(t, peerJob); out.Recorded || !out.Stopped || !out.Canceled || out.CloseFailed {
		t.Fatal("peer cleanup lost its distinct result", out)
	}
	lifeUsage(t, o, 1, 2)
	if err := badInbound.Close(); !errors.Is(err, bodyowner.ErrTransferred) {
		t.Fatal("joined Close failure refunded uncertain resource", err)
	}
	o.Stop()
	g.Retire()
	lifeUsage(t, o, 1, 2)
	lifeCounts(t, bad, 1, 1)
	lifeCounts(t, peer, 1, 1)
}

func TestReadRetireStopAndCloseFailureFlagsSurviveTogether(t *testing.T) {
	o, g, ctx, _ := lifeFixture(t)
	s := newLifeSource(t, false, true, "A", errors.New("synthetic read failure"), errors.New("synthetic close failure"))
	j := lifeBegin(t, g, ctx, lifeInbound(t, o), s, 1)
	lifeEntered(t, s.closeEntered)
	g.Retire()
	o.Stop()
	s.releaseClose()
	out := lifeJoined(t, j)
	if out.Recorded || !out.Canceled || !out.Retired || !out.Stopped || !out.CloseFailed || out.ReadFailure != bodyowner.ReadError {
		t.Fatal("one failure erased another", out)
	}
	lifeUsage(t, o, 1, 2)
	lifeCounts(t, s, 1, 1)
}

func TestFourCapturesShareCopiedOwnerAndCrossGenerationCapacity(t *testing.T) {
	o, first, ctx, cancel := lifeFixture(t)
	copyOwner := *o
	second, err := copyOwner.NewGeneration("11111111111111111111111111111111")
	if err != nil {
		t.Fatal(err)
	}
	owners := []*bodyowner.Owner{o, &copyOwner}
	gens := []*bodyowner.Generation{first, second}
	var jobs []*bodyowner.Job
	var sources []*lifeSource
	for i := range 4 {
		s := newLifeSource(t, true, false, "A", io.EOF, nil)
		j := lifeBegin(t, gens[i%2], ctx, lifeInbound(t, owners[(i+1)%2]), s, 1)
		lifeEntered(t, s.readEntered)
		jobs = append(jobs, j)
		sources = append(sources, s)
	}
	for _, owner := range owners {
		lifeUsage(t, owner, 4, 8)
		if in, err := owner.ReserveInbound(); in != nil || !errors.Is(err, bodyowner.ErrCapacity) {
			t.Fatal("copied owner bypassed shared capacity", err)
		}
	}
	cancel()
	for _, s := range sources {
		lifeEntered(t, s.closeEntered)
	}
	lifeUsage(t, o, 4, 8)
	for _, s := range sources {
		s.releaseRead()
	}
	for _, j := range jobs {
		if out := lifeJoined(t, j); out.Recorded || !out.Canceled {
			t.Fatal("canceled saturated job published", out)
		}
	}
	lifeUsage(t, o, 0, 0)
}

func TestEightFreeInboundsLeaveNoOutboundReservation(t *testing.T) {
	o, g, ctx, _ := lifeFixture(t)
	var inbounds []*bodyowner.Inbound
	for range 8 {
		inbounds = append(inbounds, lifeInbound(t, o))
	}
	lifeUsage(t, o, 0, 8)
	s := newLifeSource(t, true, false, "A", io.EOF, nil)
	if j, err := g.Begin(ctx, inbounds[0], s, 1); j != nil || !errors.Is(err, bodyowner.ErrCapacity) {
		t.Fatal("Begin ignored outbound slot requirement", err)
	}
	lifeCounts(t, s, 0, 0)
	lifeUsage(t, o, 0, 8)
	if err := inbounds[7].Close(); err != nil {
		t.Fatal(err)
	}
	j := lifeBegin(t, g, ctx, inbounds[0], s, 1)
	lifeEntered(t, s.readEntered)
	lifeUsage(t, o, 1, 8)
	s.releaseRead()
	if out := lifeJoined(t, j); !out.Recorded {
		t.Fatal("available outbound reservation did not admit", out)
	}
	for _, in := range inbounds {
		if err := in.Close(); err != nil {
			t.Fatal(err)
		}
	}
	lifeUsage(t, o, 0, 0)
}

func TestCopiedInboundClosesAndTransfersOnlyOnce(t *testing.T) {
	o, g, ctx, _ := lifeFixture(t)
	free := lifeInbound(t, o)
	freeCopy := *free
	if err := freeCopy.Close(); err != nil {
		t.Fatal(err)
	}
	lifeUsage(t, o, 0, 0)
	refused := newLifeSource(t, false, false, "", io.EOF, nil)
	if j, err := g.Begin(ctx, free, refused, 0); j != nil || !errors.Is(err, bodyowner.ErrClosed) {
		t.Fatal("closed alias remained admissible", err)
	}
	lifeCounts(t, refused, 0, 0)
	in := lifeInbound(t, o)
	copyInbound := *in
	s := newLifeSource(t, true, false, "A", io.EOF, nil)
	j := lifeBegin(t, g, ctx, in, s, 1)
	lifeEntered(t, s.readEntered)
	if extra, err := g.Begin(ctx, &copyInbound, refused, 0); extra != nil || !errors.Is(err, bodyowner.ErrTransferred) {
		t.Fatal("copied inbound created duplicate ownership", err)
	}
	if err := copyInbound.Close(); !errors.Is(err, bodyowner.ErrTransferred) {
		t.Fatal("copied inbound released live charge", err)
	}
	lifeCounts(t, refused, 0, 0)
	lifeUsage(t, o, 1, 2)
	s.releaseRead()
	lifeJoined(t, j)
	if err := copyInbound.Close(); err != nil {
		t.Fatal(err)
	}
	lifeUsage(t, o, 0, 0)
}

type lifeDeadlineOnly struct{ deadline time.Time }

func (c lifeDeadlineOnly) Deadline() (time.Time, bool) { return c.deadline, true }
func (lifeDeadlineOnly) Done() <-chan struct{}         { return nil }
func (lifeDeadlineOnly) Err() error                    { return nil }
func (lifeDeadlineOnly) Value(any) any                 { return nil }

func TestAbsoluteDeadlinePreventsLatePublicationWithoutOriginalTimerSignal(t *testing.T) {
	o, g, _, _ := lifeFixture(t)
	deadline := time.Now().Add(100 * time.Millisecond)
	s := newLifeSource(t, false, true, "A", io.EOF, nil)
	j := lifeBegin(t, g, lifeDeadlineOnly{deadline: deadline}, lifeInbound(t, o), s, 1)
	lifeEntered(t, s.closeEntered)
	// The deadline is the injected fault, not a sleep used to infer success.
	expiry, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	<-expiry.Done()
	s.releaseClose()
	out := lifeJoined(t, j)
	if out.Recorded || !out.Canceled {
		t.Fatal("elapsed original deadline published", out)
	}
	lifeUsage(t, o, 0, 0)
}

func TestAdmissionErrorOrderPreservesCallerOwnership(t *testing.T) {
	type input struct {
		g      *bodyowner.Generation
		in     *bodyowner.Inbound
		ctx    context.Context
		source io.ReadCloser
		length int
	}
	type testCase struct {
		name    string
		change  func(*testing.T, *bodyowner.Owner, *bodyowner.Generation, *bodyowner.Inbound, context.CancelFunc, *input)
		want    error
		sockets int
	}
	cases := []testCase{
		{"nil-context", func(_ *testing.T, _ *bodyowner.Owner, _ *bodyowner.Generation, _ *bodyowner.Inbound, _ context.CancelFunc, a *input) {
			a.ctx = nil
		}, bodyowner.ErrInput, 1},
		{"unbounded-context", func(_ *testing.T, _ *bodyowner.Owner, _ *bodyowner.Generation, _ *bodyowner.Inbound, _ context.CancelFunc, a *input) {
			a.ctx = context.Background()
		}, bodyowner.ErrInput, 1},
		{"nil-source", func(_ *testing.T, _ *bodyowner.Owner, _ *bodyowner.Generation, _ *bodyowner.Inbound, _ context.CancelFunc, a *input) {
			a.source = nil
		}, bodyowner.ErrInput, 1},
		{"negative-length", func(_ *testing.T, _ *bodyowner.Owner, _ *bodyowner.Generation, _ *bodyowner.Inbound, _ context.CancelFunc, a *input) {
			a.length = -1
		}, bodyowner.ErrInput, 1},
		{"oversize-length", func(_ *testing.T, _ *bodyowner.Owner, _ *bodyowner.Generation, _ *bodyowner.Inbound, _ context.CancelFunc, a *input) {
			a.length = 4097
		}, bodyowner.ErrInput, 1},
		{"nil-inbound", func(_ *testing.T, _ *bodyowner.Owner, _ *bodyowner.Generation, _ *bodyowner.Inbound, _ context.CancelFunc, a *input) {
			a.in = nil
		}, bodyowner.ErrInput, 1},
		{"nil-generation", func(_ *testing.T, _ *bodyowner.Owner, _ *bodyowner.Generation, _ *bodyowner.Inbound, _ context.CancelFunc, a *input) {
			a.g = nil
		}, bodyowner.ErrInput, 1},
		{"zero-generation", func(_ *testing.T, _ *bodyowner.Owner, _ *bodyowner.Generation, _ *bodyowner.Inbound, _ context.CancelFunc, a *input) {
			a.g = new(bodyowner.Generation)
		}, bodyowner.ErrInput, 1},
		{"foreign-inbound", func(t *testing.T, _ *bodyowner.Owner, _ *bodyowner.Generation, _ *bodyowner.Inbound, _ context.CancelFunc, a *input) {
			a.in = lifeInbound(t, bodyowner.New())
		}, bodyowner.ErrInput, 1},
		{"invalid-before-stopped", func(_ *testing.T, o *bodyowner.Owner, _ *bodyowner.Generation, _ *bodyowner.Inbound, _ context.CancelFunc, a *input) {
			o.Stop()
			a.length = -1
		}, bodyowner.ErrInput, 1},
		{"stopped-before-retired-canceled", func(_ *testing.T, o *bodyowner.Owner, g *bodyowner.Generation, _ *bodyowner.Inbound, cancel context.CancelFunc, _ *input) {
			g.Retire()
			o.Stop()
			cancel()
		}, bodyowner.ErrStopped, 1},
		{"retired-before-canceled", func(_ *testing.T, _ *bodyowner.Owner, g *bodyowner.Generation, _ *bodyowner.Inbound, cancel context.CancelFunc, _ *input) {
			g.Retire()
			cancel()
		}, bodyowner.ErrRetired, 1},
		{"canceled-before-closed", func(_ *testing.T, _ *bodyowner.Owner, _ *bodyowner.Generation, in *bodyowner.Inbound, cancel context.CancelFunc, _ *input) {
			_ = in.Close()
			cancel()
		}, context.Canceled, 0},
		{"absolute-expiry-before-closed", func(_ *testing.T, _ *bodyowner.Owner, _ *bodyowner.Generation, in *bodyowner.Inbound, _ context.CancelFunc, a *input) {
			_ = in.Close()
			a.ctx = lifeDeadlineOnly{deadline: time.Now().Add(-time.Second)}
		}, context.DeadlineExceeded, 0},
		{"closed", func(_ *testing.T, _ *bodyowner.Owner, _ *bodyowner.Generation, in *bodyowner.Inbound, _ context.CancelFunc, _ *input) {
			_ = in.Close()
		}, bodyowner.ErrClosed, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o, g, ctx, cancel := lifeFixture(t)
			in := lifeInbound(t, o)
			s := newLifeSource(t, false, false, "", io.EOF, nil)
			a := input{g: g, in: in, ctx: ctx, source: s}
			tc.change(t, o, g, in, cancel, &a)
			j, err := a.g.Begin(a.ctx, a.in, a.source, a.length)
			if j != nil {
				lifeTrack(t, j, s)
			}
			if j != nil || !errors.Is(err, tc.want) {
				t.Fatal("incorrect admission/error order", err)
			}
			lifeCounts(t, s, 0, 0)
			lifeUsage(t, o, 0, tc.sockets)
		})
	}
}

func TestNilZeroHandlesAndGenerationGrammar(t *testing.T) {
	var nilOwner *bodyowner.Owner
	var zeroOwner bodyowner.Owner
	ownerCopy := zeroOwner
	for _, o := range []*bodyowner.Owner{nilOwner, &zeroOwner, &ownerCopy} {
		if in, err := o.ReserveInbound(); in != nil || !errors.Is(err, bodyowner.ErrInput) {
			t.Fatal("nil/zero owner acquired", err)
		}
		if g, err := o.NewGeneration(lifeGeneration); g != nil || !errors.Is(err, bodyowner.ErrInput) {
			t.Fatal("nil/zero owner constructed generation", err)
		}
		o.Stop()
		lifeUsage(t, o, 0, 0)
	}
	var nilInbound *bodyowner.Inbound
	var zeroInbound bodyowner.Inbound
	copyInbound := zeroInbound
	for _, in := range []*bodyowner.Inbound{nilInbound, &zeroInbound, &copyInbound} {
		if err := in.Close(); !errors.Is(err, bodyowner.ErrInput) {
			t.Fatal("nil/zero inbound became usable", err)
		}
	}
	var nilGeneration *bodyowner.Generation
	var zeroGeneration bodyowner.Generation
	nilGeneration.Retire()
	zeroGeneration.Retire()
	var nilJob *bodyowner.Job
	var zeroJob bodyowner.Job
	copyJob := zeroJob
	for _, j := range []*bodyowner.Job{nilJob, &zeroJob, &copyJob} {
		if out, err := j.Wait(context.Background()); !errors.Is(err, bodyowner.ErrInput) || out.Joined || out.Recorded {
			t.Fatal("nil/zero Job became usable", err)
		}
		if out := j.Outcome(); out.Joined || out.Recorded || out.Record.Generation != "" || len(out.Record.Body) != 0 {
			t.Fatal("nil/zero Job exposed a record", out)
		}
	}
	o := bodyowner.New()
	for _, token := range []string{"", "0000000000000000000000000000000", "000000000000000000000000000000000", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "gggggggggggggggggggggggggggggggg", "0000000000000000000000000000000\n"} {
		if g, err := o.NewGeneration(token); g != nil || !errors.Is(err, bodyowner.ErrInput) {
			t.Fatal("invalid generation accepted", err)
		}
	}
}

// A caller method can wait at a finite gate, letting the test probe owner locks
// without making a self-deadlock that cannot be released during cleanup.
type lifeContextProbe struct {
	base              context.Context
	target            string
	entered, release  chan struct{}
	once, free        sync.Once
	values, callbacks atomic.Int32
}

func (c *lifeContextProbe) gate(method string) {
	if c.target == method {
		c.once.Do(func() { close(c.entered); <-c.release })
	}
}
func (c *lifeContextProbe) Deadline() (time.Time, bool) { c.gate("Deadline"); return c.base.Deadline() }
func (c *lifeContextProbe) Done() <-chan struct{}       { c.gate("Done"); return c.base.Done() }
func (c *lifeContextProbe) Err() error                  { c.gate("Err"); return c.base.Err() }
func (c *lifeContextProbe) Value(any) any               { c.values.Add(1); return nil }
func (c *lifeContextProbe) AfterFunc(func()) func() bool {
	c.callbacks.Add(1)
	return func() bool { return true }
}
func (c *lifeContextProbe) unblock() { c.free.Do(func() { close(c.release) }) }

func TestCallerContextMethodsStayOutsideOwnerMutex(t *testing.T) {
	for _, method := range []string{"Deadline", "Done", "Err"} {
		t.Run(method, func(t *testing.T) {
			o, g, ctx, _ := lifeFixture(t)
			probe := &lifeContextProbe{base: ctx, target: method, entered: make(chan struct{}), release: make(chan struct{})}
			t.Cleanup(probe.unblock)
			s := newLifeSource(t, false, false, "", io.EOF, nil)
			in := lifeInbound(t, o)
			type result struct {
				job *bodyowner.Job
				err error
			}
			begun := make(chan result, 1)
			go func() { j, err := g.Begin(probe, in, s, 0); begun <- result{j, err} }()
			// Registered before assertions so the owned Begin is always joined.
			var got result
			joined := false
			t.Cleanup(func() {
				probe.unblock()
				if !joined {
					select {
					case got = <-begun:
						joined = true
					case <-time.After(lifeBound):
						t.Error("Begin did not join after context gate release")
					}
				}
				if got.job != nil {
					s.releaseAll()
					wait, cancel := context.WithTimeout(context.Background(), lifeBound)
					defer cancel()
					if out, err := got.job.Wait(wait); err != nil || !out.Joined {
						t.Error("context fixture did not join", err)
					}
				}
			})
			lifeEntered(t, probe.entered)
			usageDone := make(chan struct{})
			go func() { _, _ = o.NewGeneration(lifeGeneration); close(usageDone) }()
			select {
			case <-usageDone:
			case <-time.After(lifeBound):
				t.Error("caller Context method executed while owner mutex was held")
			}
			probe.unblock()
			lifeEntered(t, usageDone)
			select {
			case got = <-begun:
				joined = true
			case <-time.After(lifeBound):
				t.Fatal("Begin did not return")
			}
			if got.err != nil || got.job == nil {
				t.Fatal("context observation refused valid input", got.err)
			}
			if out := lifeJoined(t, got.job); !out.Recorded {
				t.Fatal("valid custom context did not record", out)
			}
			if probe.values.Load() != 0 || probe.callbacks.Load() != 0 {
				t.Fatal("caller Values or cancellation hooks were propagated")
			}
		})
	}
}

func TestOriginalDoneCancelsWithoutCallerCancellationHooks(t *testing.T) {
	o, g, ctx, cancel := lifeFixture(t)
	probe := &lifeContextProbe{base: ctx, entered: make(chan struct{}), release: make(chan struct{})}
	t.Cleanup(probe.unblock)
	s := newLifeSource(t, true, false, "A", io.EOF, nil)
	j := lifeBegin(t, g, probe, lifeInbound(t, o), s, 1)
	lifeEntered(t, s.readEntered)
	cancel()
	lifeEntered(t, s.closeEntered)
	if out := lifePending(t, j); !out.Canceled {
		t.Fatal("original Done was not observed", out)
	}
	s.releaseRead()
	if out := lifeJoined(t, j); out.Recorded || !out.Canceled {
		t.Fatal("original cancellation was lost", out)
	}
	if probe.values.Load() != 0 || probe.callbacks.Load() != 0 {
		t.Fatal("caller cancellation hooks were propagated")
	}
	lifeUsage(t, o, 0, 0)
}

func TestReadAndCloseCallsStayOutsideOwnerMutex(t *testing.T) {
	for _, stage := range []string{"Read", "Close"} {
		t.Run(stage, func(t *testing.T) {
			o, g, ctx, _ := lifeFixture(t)
			s := newLifeSource(t, stage == "Read", stage == "Close", "A", io.EOF, nil)
			j := lifeBegin(t, g, ctx, lifeInbound(t, o), s, 1)
			if stage == "Read" {
				lifeEntered(t, s.readEntered)
			} else {
				lifeEntered(t, s.closeEntered)
			}
			done := make(chan struct{})
			go func() { _, _ = o.NewGeneration(lifeGeneration); close(done) }()
			select {
			case <-done:
			case <-time.After(lifeBound):
				t.Error("source I/O ran under owner mutex")
			}
			s.releaseAll()
			lifeEntered(t, done)
			lifeJoined(t, j)
		})
	}
}

func TestConcurrentCopiedStopRetireAndCancellationCannotPublish(t *testing.T) {
	for range 8 {
		o, g, ctx, cancel := lifeFixture(t)
		ownerCopy, generationCopy := *o, *g
		s := newLifeSource(t, true, false, "A", io.EOF, nil)
		j := lifeBegin(t, g, ctx, lifeInbound(t, o), s, 1)
		jobCopy := *j
		lifeEntered(t, s.readEntered)
		start := make(chan struct{})
		var workers sync.WaitGroup
		workers.Go(func() { <-start; ownerCopy.Stop() })
		workers.Go(func() { <-start; generationCopy.Retire() })
		workers.Go(func() { <-start; cancel() })
		close(start)
		workers.Wait()
		lifeEntered(t, s.closeEntered)
		out := lifePending(t, &jobCopy)
		if !out.Stopped || !out.Retired || !out.Canceled {
			t.Fatal("copied concurrent lifecycle state diverged", out)
		}
		lifeUsage(t, o, 1, 2)
		s.releaseRead()
		out = lifeJoined(t, &jobCopy)
		if out.Recorded || !out.Stopped || !out.Retired || !out.Canceled {
			t.Fatal("concurrent lifecycle operation published", out)
		}
		lifeUsage(t, o, 0, 0)
		lifeCounts(t, s, 1, 1)
	}
}

func TestCopiedJobsShareConcurrentWaitAndOutcome(t *testing.T) {
	o, g, ctx, _ := lifeFixture(t)
	s := newLifeSource(t, true, false, "AB", io.EOF, nil)
	j := lifeBegin(t, g, ctx, lifeInbound(t, o), s, 2)
	lifeEntered(t, s.readEntered)
	observer, cancelObserver := context.WithTimeout(context.Background(), lifeBound)
	type waitResult struct {
		out bodyowner.Outcome
		err error
	}
	const waiters = 8
	results := make(chan waitResult, waiters)
	started := make(chan struct{}, waiters)
	received := 0
	const readers = 4
	observations := make(chan bool, readers)
	observed, launchedReaders := 0, 0
	t.Cleanup(func() {
		s.releaseAll()
		cancelObserver()
		deadline := time.NewTimer(lifeBound)
		defer deadline.Stop()
		for received < waiters {
			select {
			case <-results:
				received++
			case <-deadline.C:
				t.Error("copied waiters did not join during finite teardown")
				return
			}
		}
		for observed < launchedReaders {
			select {
			case <-observations:
				observed++
			case <-deadline.C:
				t.Error("copied Outcome readers did not join during finite teardown")
				return
			}
		}
	})
	for range waiters {
		copyJob := *j
		go func() {
			started <- struct{}{}
			out, err := copyJob.Wait(observer)
			results <- waitResult{out: out, err: err}
		}()
	}
	for range waiters {
		select {
		case <-started:
		case <-observer.Done():
			t.Fatal("copied waiter did not start")
		}
	}
	for range readers {
		launchedReaders++
		copyJob := *j
		go func() {
			valid := true
			for range 32 {
				out := copyJob.Outcome()
				valid = valid && !out.Joined && !out.Recorded && out.Record.Generation == "" && len(out.Record.Body) == 0
			}
			observations <- valid
		}()
	}
	// Read remains held until every observer completed its finite operations.
	for observed < launchedReaders {
		select {
		case valid := <-observations:
			observed++
			if !valid {
				t.Error("concurrent copied Outcome exposed pending bytes or completion")
			}
		case <-observer.Done():
			t.Fatal("copied Outcome reader did not return")
		}
	}
	lifeUsage(t, o, 1, 2)
	s.releaseRead()
	for received < waiters {
		select {
		case result := <-results:
			received++
			if result.err != nil || !result.out.Joined || !result.out.Recorded || result.out.Record.Generation != lifeGeneration || string(result.out.Record.Body) != "AB" {
				t.Error("copied Wait did not share exact completion", result.err)
			}
			if len(result.out.Record.Body) > 0 {
				result.out.Record.Body[0] = 'Z'
			}
		case <-observer.Done():
			t.Fatal("copied Wait did not join after Read release")
		}
	}
	if out := j.Outcome(); !out.Recorded || string(out.Record.Body) != "AB" {
		t.Fatal("one concurrent waiter mutated private recording", out)
	}
	lifeUsage(t, o, 0, 0)
	lifeCounts(t, s, 1, 1)
}
