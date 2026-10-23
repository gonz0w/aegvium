// SPDX-License-Identifier: BSD-3-Clause
package capacity

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"unsafe"
)

func TestIndependentStateTraces(t *testing.T) {
	data, err := os.ReadFile("testdata/independent.json")
	if err != nil {
		t.Fatal(err)
	}
	// Independent literal expectations were frozen before this Go source existed.
	hash := sha256.Sum256(data)
	if hex.EncodeToString(hash[:]) != "021fe424556a7c606853866c84b3fe8a4a6e4a763ad84f653fd11493b82f6e16" {
		t.Fatal("independent trace freeze changed")
	}
	var fixture struct {
		Traces []struct {
			ID     string
			Owners []string
			Steps  []struct {
				Op, Owner, Generation, Inbound, Lease, Result, Token string
				Error                                                string           `json:"expect_error"`
				Nil                                                  bool             `json:"expect_nil"`
				Usage                                                map[string]Usage `json:"expect_usage"`
				Pending                                              map[string]int   `json:"expect_pending"`
				ExpectedGeneration                                   *string          `json:"expect_generation"`
				Value                                                json.RawMessage  `json:"expect_value"`
			}
		}
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	operations := 0
	for _, trace := range fixture.Traces {
		t.Run(trace.ID, func(t *testing.T) {
			owners := map[string]*Owner{"nil": nil, "zero": {}}
			generations := map[string]*Generation{"nil": nil, "zero": {}}
			inbounds := map[string]*Inbound{"nil": nil, "zero": {}}
			leases := map[string]*Lease{"nil": nil, "zero": {}}
			for _, name := range trace.Owners {
				owners[name] = New()
			}
			for i, step := range trace.Steps {
				operations++
				var err error
				pointer, absent := false, false
				switch step.Op {
				case "new_generation":
					value, e := required(t, owners, step.Owner).NewGeneration(step.Token)
					generations[step.Result], err, pointer, absent = value, e, true, value == nil
				case "reserve_inbound":
					value, e := required(t, owners, step.Owner).ReserveInbound()
					inbounds[step.Result], err, pointer, absent = value, e, true, value == nil
				case "try_request":
					value, e := required(t, generations, step.Generation).TryRequest(required(t, inbounds, step.Inbound))
					leases[step.Result], err, pointer, absent = value, e, true, value == nil
				case "close_inbound":
					err = required(t, inbounds, step.Inbound).Close()
				case "close_lease":
					required(t, leases, step.Lease).Close()
				case "retire":
					required(t, generations, step.Generation).Retire()
				case "stop":
					required(t, owners, step.Owner).Stop()
				case "lease_generation":
					if step.ExpectedGeneration == nil || required(t, leases, step.Lease).Generation() != *step.ExpectedGeneration {
						t.Fatal("generation identity mismatch", i)
					}
				case "usage":
					var want Usage
					if len(step.Value) == 0 || json.Unmarshal(step.Value, &want) != nil || required(t, owners, step.Owner).Usage() != want {
						t.Fatal("explicit usage observation mismatch", i)
					}
				case "pending":
					var want int
					if len(step.Value) == 0 || json.Unmarshal(step.Value, &want) != nil || required(t, generations, step.Generation).Pending() != want {
						t.Fatal("explicit pending observation mismatch", i)
					}
				default:
					t.Fatal("unknown independent operation", step.Op)
				}
				if errorName(err) != step.Error || pointer && absent != step.Nil {
					t.Fatalf("step %d %s: error=%s nil=%v", i, step.Op, errorName(err), absent)
				}
				for name, want := range step.Usage {
					if got := required(t, owners, name).Usage(); got != want {
						t.Fatalf("step %d owner %s: got %+v want %+v", i, name, got, want)
					}
				}
				for name, want := range step.Pending {
					if got := required(t, generations, name).Pending(); got != want {
						t.Fatalf("step %d generation %s: got %d want %d", i, name, got, want)
					}
				}
			}
		})
	}
	if len(fixture.Traces) != 9 || operations != 164 {
		t.Fatal("incomplete independent traces", len(fixture.Traces), operations)
	}
}

func required[T any](t *testing.T, values map[string]T, name string) T {
	t.Helper()
	value, exists := values[name]
	if !exists {
		t.Fatal("unknown fixture alias", name)
	}
	return value
}

func errorName(err error) string {
	for name, value := range map[string]error{
		"ErrInput": ErrInput, "ErrStopped": ErrStopped, "ErrRetired": ErrRetired,
		"ErrCapacity": ErrCapacity, "ErrClosed": ErrClosed, "ErrTransferred": ErrTransferred,
	} {
		if errors.Is(err, value) {
			return name
		}
	}
	if err != nil {
		return "unknown error"
	}
	return ""
}

func TestGenerationDetachedAndObservationsCopied(t *testing.T) {
	o := New()
	backing := strings.Repeat("a", 8192)
	token := backing[:32]
	g, err := o.NewGeneration(token)
	if err != nil {
		t.Fatal(err)
	}
	in, err := o.ReserveInbound()
	if err != nil {
		t.Fatal(err)
	}
	l, err := g.TryRequest(in)
	if err != nil {
		t.Fatal(err)
	}
	if l.Generation() != token || unsafe.StringData(l.Generation()) == unsafe.StringData(token) {
		t.Fatal("generation retains caller backing allocation")
	}
	view := o.Usage()
	view.Requests, view.Sockets = -1, -1
	if o.Usage() != (Usage{1, 2}) || g.Pending() != 1 {
		t.Fatal("observation aliases owner state")
	}
	o.Stop()
	g.Retire()
	if o.Usage() != (Usage{1, 2}) || g.Pending() != 1 {
		t.Fatal("retirement released resources")
	}
	l.Close()
	if o.Usage() != (Usage{}) || g.Pending() != 0 || l.Generation() != token {
		t.Fatal("closure lost accounting or historical identity")
	}
}

func TestConcurrentSharedCapacity(t *testing.T) {
	for range 32 {
		o := New()
		first, _ := o.NewGeneration(strings.Repeat("a", 32))
		second, _ := o.NewGeneration(strings.Repeat("b", 32))
		generations := []*Generation{first, second}
		start, release := make(chan struct{}), make(chan struct{})
		var attempted, finished sync.WaitGroup
		attempted.Add(32)
		for i := range 32 {
			finished.Go(func() {
				<-start
				in, err := o.ReserveInbound()
				if err != nil {
					if !errors.Is(err, ErrCapacity) {
						t.Error(err)
					}
					attempted.Done()
					return
				}
				l, err := generations[i%2].TryRequest(in)
				if err != nil {
					if !errors.Is(err, ErrCapacity) {
						t.Error(err)
					}
					if e := in.Close(); e != nil {
						t.Error(e)
					}
				}
				if u := o.Usage(); u.Requests > MaxRequests || u.Sockets > MaxSockets || u.Requests < 0 || u.Sockets < 0 {
					t.Error("shared capacity exceeded", u)
				}
				attempted.Done()
				<-release
				l.Close()
			})
		}
		close(start)
		attempted.Wait()
		u := o.Usage()
		if u.Sockets != 2*u.Requests || first.Pending()+second.Pending() != u.Requests {
			t.Error("failed acquisition leaked or transferred reservations", u)
		}
		close(release)
		finished.Wait()
		if o.Usage() != (Usage{}) || first.Pending() != 0 || second.Pending() != 0 {
			t.Fatal("concurrent cleanup leaked accounting")
		}
	}
}

func TestConcurrentStopRetireAndClose(t *testing.T) {
	for range 32 {
		o := New()
		g, _ := o.NewGeneration(strings.Repeat("c", 32))
		in, _ := o.ReserveInbound()
		l, _ := g.TryRequest(in)
		var workers sync.WaitGroup
		start := make(chan struct{})
		for i := range 32 {
			workers.Go(func() {
				<-start
				switch i % 4 {
				case 0:
					o.Stop()
				case 1:
					g.Retire()
				case 2:
					l.Close()
				case 3:
					if err := in.Close(); err != nil && !errors.Is(err, ErrTransferred) {
						t.Error(err)
					}
				}
				if l.Generation() != strings.Repeat("c", 32) {
					t.Error("concurrent close changed identity")
				}
				_ = o.Usage()
				_ = g.Pending()
			})
		}
		close(start)
		workers.Wait()
		if o.Usage() != (Usage{}) || g.Pending() != 0 {
			t.Fatal("double release or leaked reservations")
		}
		if v, err := o.ReserveInbound(); v != nil || !errors.Is(err, ErrStopped) {
			t.Fatal("acquisition crossed completed stop")
		}
	}
}

func TestConcurrentAcquisitionAndRetirement(t *testing.T) {
	for _, stop := range []bool{false, true} {
		for range 32 {
			o := New()
			g, _ := o.NewGeneration(strings.Repeat("d", 32))
			in, _ := o.ReserveInbound()
			start := make(chan struct{})
			var workers sync.WaitGroup
			var lease *Lease
			var result error
			workers.Go(func() {
				<-start
				lease, result = g.TryRequest(in)
			})
			workers.Go(func() {
				<-start
				if stop {
					o.Stop()
				} else {
					g.Retire()
				}
			})
			close(start)
			workers.Wait()
			refusal := ErrRetired
			if stop {
				refusal = ErrStopped
			}
			if lease == nil {
				if !errors.Is(result, refusal) || o.Usage() != (Usage{0, 1}) || g.Pending() != 0 {
					t.Fatal("failed racing transfer changed accounting", result)
				}
			} else if result != nil || o.Usage() != (Usage{1, 2}) || g.Pending() != 1 {
				t.Fatal("completed racing transfer lost charge", result)
			}
			if next, err := g.TryRequest(in); next != nil || !errors.Is(err, refusal) {
				t.Fatal("lease crossed completed retirement/stop", err)
			}
			lease.Close()
			if err := in.Close(); err != nil || o.Usage() != (Usage{}) || g.Pending() != 0 {
				t.Fatal("racing lease did not close exactly once", err)
			}
		}
	}
}
