// SPDX-License-Identifier: BSD-3-Clause
package capacity_test

import (
	"errors"
	"sync"
	"testing"

	"github.com/gonz0w/aegvium/internal/capacity"
)

const generation = "00000000000000000000000000000000"

func fixture(t *testing.T) (*capacity.Owner, *capacity.Generation) {
	t.Helper()
	o := capacity.New()
	g, err := o.NewGeneration(generation)
	if err != nil {
		t.Fatal(err)
	}
	return o, g
}

func leaseFixture(t *testing.T) (*capacity.Owner, *capacity.Generation, *capacity.Inbound, *capacity.Lease) {
	t.Helper()
	o, g := fixture(t)
	in, err := o.ReserveInbound()
	if err != nil {
		t.Fatal(err)
	}
	l, err := g.TryRequest(in)
	if err != nil {
		t.Fatal(err)
	}
	return o, g, in, l
}

func usage(t *testing.T, o *capacity.Owner, requests, sockets int) {
	t.Helper()
	if got := o.Usage(); got != (capacity.Usage{Requests: requests, Sockets: sockets}) {
		t.Fatalf("accounting got %+v; want requests=%d sockets=%d", got, requests, sockets)
	}
}

func TestCopiedFreeInboundClosesOneReservation(t *testing.T) {
	o, g := fixture(t)
	in, err := o.ReserveInbound()
	if err != nil {
		t.Fatal(err)
	}
	copy := *in
	if err := copy.Close(); err != nil {
		t.Fatal(err)
	}
	usage(t, o, 0, 0)
	if err := in.Close(); err != nil {
		t.Fatal(err)
	}
	usage(t, o, 0, 0)
	for _, handle := range []*capacity.Inbound{in, &copy} {
		if l, err := g.TryRequest(handle); l != nil || !errors.Is(err, capacity.ErrClosed) {
			t.Fatal("a closed alias acquired a request", err)
		}
	}
}

func TestCopiedInboundCannotTransferTwice(t *testing.T) {
	o, g := fixture(t)
	in, err := o.ReserveInbound()
	if err != nil {
		t.Fatal(err)
	}
	copy := *in
	l, err := g.TryRequest(in)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	other, err := g.TryRequest(&copy)
	if other != nil {
		defer other.Close()
	}
	if other != nil || !errors.Is(err, capacity.ErrTransferred) {
		t.Fatal("copied inbound created a duplicate lease", err)
	}
	if err := copy.Close(); !errors.Is(err, capacity.ErrTransferred) {
		t.Fatal("copied inbound released a live transferred slot", err)
	}
	usage(t, o, 1, 2)
	if g.Pending() != 1 {
		t.Fatal("duplicate transfer changed pending count")
	}
	l.Close()
	if err := copy.Close(); err != nil {
		t.Fatal("closed transferred alias is not idempotent", err)
	}
	usage(t, o, 0, 0)
}

func TestCopiedLeaseClosesExactlyOnce(t *testing.T) {
	o, g, in, l := leaseFixture(t)
	copy := *l
	l.Close()
	copy.Close()
	usage(t, o, 0, 0)
	if g.Pending() != 0 || l.Generation() != generation || copy.Generation() != generation {
		t.Fatal("copied close lost pending accounting or generation identity")
	}
	if err := in.Close(); err != nil {
		t.Fatal(err)
	}
	usage(t, o, 0, 0)
	closedCopy := copy
	closedCopy.Close()
	usage(t, o, 0, 0)
}

func TestConcurrentCopiedLeaseClose(t *testing.T) {
	for range 16 {
		o, g, _, l := leaseFixture(t)
		copies := make([]capacity.Lease, 16)
		for i := range copies {
			copies[i] = *l
		}
		start := make(chan struct{})
		var done sync.WaitGroup
		for i := range copies {
			done.Go(func() {
				<-start
				copies[i].Close()
			})
		}
		close(start)
		done.Wait()
		l.Close()
		usage(t, o, 0, 0)
		if g.Pending() != 0 {
			t.Fatal("concurrent alias closure changed pending more than once")
		}
	}
}

func TestCopiedGenerationSharesPendingAndRetirement(t *testing.T) {
	o, g := fixture(t)
	copy := *g
	in, err := o.ReserveInbound()
	if err != nil {
		t.Fatal(err)
	}
	l, err := copy.TryRequest(in)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if g.Pending() != 1 || copy.Pending() != 1 {
		t.Fatal("generation copies have detached pending counts")
	}
	copy.Retire()
	free, err := o.ReserveInbound()
	if err != nil {
		t.Fatal(err)
	}
	defer free.Close()
	for _, handle := range []*capacity.Generation{g, &copy} {
		if extra, err := handle.TryRequest(free); extra != nil || !errors.Is(err, capacity.ErrRetired) {
			if extra != nil {
				extra.Close()
			}
			t.Fatal("generation alias bypassed completed retirement", err)
		}
	}
	usage(t, o, 1, 3)
	l.Close()
	if g.Pending() != 0 || copy.Pending() != 0 {
		t.Fatal("generation aliases disagree after closure")
	}
}

func TestCopiedGenerationRetiresOriginal(t *testing.T) {
	o, g := fixture(t)
	copy := *g
	copy.Retire()
	in, err := o.ReserveInbound()
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	if l, err := g.TryRequest(in); l != nil || !errors.Is(err, capacity.ErrRetired) {
		if l != nil {
			l.Close()
		}
		t.Fatal("copy retirement left original generation active", err)
	}
	usage(t, o, 0, 1)
}

func TestCopiedOwnerStopStopsOriginal(t *testing.T) {
	o := capacity.New()
	copy := *o
	copy.Stop()
	if in, err := o.ReserveInbound(); in != nil || !errors.Is(err, capacity.ErrStopped) {
		if in != nil {
			_ = in.Close()
		}
		t.Fatal("copy stop left original owner active", err)
	}
	usage(t, o, 0, 0)
}

func TestCopiedOwnerSharesCapacityAndStop(t *testing.T) {
	o := capacity.New()
	copy := *o
	owners := []*capacity.Owner{o, &copy}
	first, err := o.NewGeneration(generation)
	if err != nil {
		t.Fatal(err)
	}
	second, err := copy.NewGeneration(generation)
	if err != nil {
		t.Fatal(err)
	}
	gens := []*capacity.Generation{first, second}
	var leases []*capacity.Lease
	defer func() {
		for _, l := range leases {
			l.Close()
		}
	}()
	for i := range 4 {
		in, err := owners[i%2].ReserveInbound()
		if err != nil {
			t.Fatal(err)
		}
		l, err := gens[(i+1)%2].TryRequest(in)
		if err != nil {
			_ = in.Close()
			t.Fatal("same owner alias treated as foreign", err)
		}
		leases = append(leases, l)
		for _, owner := range owners {
			usage(t, owner, i+1, 2*(i+1))
		}
	}
	for _, owner := range owners {
		if in, err := owner.ReserveInbound(); in != nil || !errors.Is(err, capacity.ErrCapacity) {
			t.Fatal("owner copy reset the shared capacity", err)
		}
	}
	copy.Stop()
	for _, owner := range owners {
		if in, err := owner.ReserveInbound(); in != nil || !errors.Is(err, capacity.ErrStopped) {
			t.Fatal("owner alias bypassed completed stop", err)
		}
		usage(t, owner, 4, 8)
	}
	for _, l := range leases {
		l.Close()
	}
	for _, owner := range owners {
		usage(t, owner, 0, 0)
	}
}

func TestCopiedZeroHandlesRemainUnavailable(t *testing.T) {
	var owner capacity.Owner
	ownerCopy := owner
	for _, o := range []*capacity.Owner{&owner, &ownerCopy} {
		if v, err := o.ReserveInbound(); v != nil || !errors.Is(err, capacity.ErrInput) {
			t.Fatal("copy initialized a zero owner", err)
		}
		o.Stop()
		usage(t, o, 0, 0)
	}
	_, live := fixture(t)
	var in capacity.Inbound
	inCopy := in
	for _, input := range []*capacity.Inbound{&in, &inCopy} {
		if err := input.Close(); !errors.Is(err, capacity.ErrInput) {
			t.Fatal("copy initialized a zero inbound", err)
		}
		if v, err := live.TryRequest(input); v != nil || !errors.Is(err, capacity.ErrInput) {
			t.Fatal("zero inbound copy acquired a lease", err)
		}
	}
	var gen capacity.Generation
	genCopy := gen
	for _, g := range []*capacity.Generation{&gen, &genCopy} {
		g.Retire()
		if g.Pending() != 0 {
			t.Fatal("zero generation has pending resources")
		}
		if v, err := g.TryRequest(nil); v != nil || !errors.Is(err, capacity.ErrInput) {
			t.Fatal("copy initialized a zero generation", err)
		}
	}
	var l capacity.Lease
	lCopy := l
	for _, lease := range []*capacity.Lease{&l, &lCopy} {
		lease.Close()
		if lease.Generation() != "" {
			t.Fatal("copy initialized a zero lease")
		}
	}
}
