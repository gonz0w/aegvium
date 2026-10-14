// SPDX-License-Identifier: BSD-3-Clause
package spike

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type labCountingCloser struct {
	calls atomic.Int32
	err   error
}

func (c *labCountingCloser) Close() error { c.calls.Add(1); return c.err }

func TestLabGenerationDrain(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	oldCloser, nextCloser := &labCountingCloser{}, &labCountingCloser{}
	old := &labRouteGeneration{waf: oldCloser, handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { close(entered); <-release; io.WriteString(w, "old") })}
	next := &labRouteGeneration{waf: nextCloser, handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "new") })}
	owner := &labRouteOwner{active: old}
	done := make(chan struct{})
	response := httptest.NewRecorder()
	go func() { owner.ServeHTTP(response, httptest.NewRequest("GET", "/", nil)); close(done) }()
	<-entered
	activated := make(chan error, 1)
	go func() { activated <- owner.replace(next) }()
	// The entered request already owns a read lease: retirement and activation
	// cannot happen until it releases that lease, regardless of scheduler timing.
	select {
	case e := <-activated:
		t.Fatal("replaced active request", e)
	case <-time.After(30 * time.Millisecond):
	}
	if oldCloser.calls.Load() != 0 {
		t.Fatal("WAF closed under live transaction")
	}
	close(release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("old request did not drain")
	}
	if e := <-activated; e != nil {
		t.Fatal(e)
	}
	if response.Body.String() != "old" || oldCloser.calls.Load() != 1 {
		t.Fatal("old generation effects/retirement changed")
	}
	response = httptest.NewRecorder()
	owner.ServeHTTP(response, httptest.NewRequest("GET", "/", nil))
	if response.Body.String() != "new" {
		t.Fatal("new generation not serving")
	}
	if e := owner.close(); e != nil {
		t.Fatal(e)
	}
	if e := owner.close(); e != nil {
		t.Fatal(e)
	}
	if nextCloser.calls.Load() != 1 {
		t.Fatal("active generation not closed exactly once")
	}
	rejectedCloser := &labCountingCloser{}
	if e := owner.replace(&labRouteGeneration{waf: rejectedCloser}); e == nil || rejectedCloser.calls.Load() != 1 {
		t.Fatal("late preparation not rejected/disposed")
	}
	response = httptest.NewRecorder()
	owner.ServeHTTP(response, httptest.NewRequest("GET", "/", nil))
	if response.Code != 503 {
		t.Fatal("closed owner served")
	}
}

func TestLabReloadRetirementFailure(t *testing.T) {
	old := &labRouteGeneration{waf: &labCountingCloser{err: errors.New("controlled close failure")}, handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})}
	next := &labRouteGeneration{waf: &labCountingCloser{}, handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "new") })}
	owner := &labRouteOwner{active: old}
	if e := owner.replace(next); !errors.Is(e, ErrLabReloadCleanup) {
		t.Fatal("post-activation cleanup error misclassified", e)
	}
	response := httptest.NewRecorder()
	owner.ServeHTTP(response, httptest.NewRequest("GET", "/", nil))
	if response.Body.String() != "new" {
		t.Fatal("activation was hidden")
	}
	owner.close()
	stopped := &labRouteOwner{active: &labRouteGeneration{waf: &labCountingCloser{}, handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})}}
	stopped.stopReloads()
	closer := &labCountingCloser{}
	if e := stopped.replace(&labRouteGeneration{waf: closer}); e == nil || closer.calls.Load() != 1 {
		t.Fatal("shutdown allowed a reload")
	}
	stopped.close()
}

func TestLabReloadKnownGood(t *testing.T) {
	effects := make(chan string, 8)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { effects <- r.Host; io.WriteString(w, "owned\n") }))
	defer backend.Close()
	original := []LabRoute{{Host: "app.test", Backend: backend.URL}}
	f, e := StartLabProxy(LabProfile{DataAddress: "127.0.0.1:0", HealthAddress: "127.0.0.1:0", Ingress: netip.MustParseAddrPort("127.0.0.1:18120"), Routes: original})
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	call := func(host string, want int) {
		r := httptest.NewRequest("GET", "/ok", nil)
		r.Host = host
		r.Header.Set("User-Agent", "Aegvium owned lab")
		r.Header.Set("Accept", "*/*")
		response := httptest.NewRecorder()
		f.routes.ServeHTTP(response, r)
		if response.Code != want {
			t.Fatalf("%s got%d want%d", host, response.Code, want)
		}
	}
	call("app.test", 200)
	if e = f.reload(original, "NotARealDirective on"); e == nil {
		t.Fatal("invalid rule preparation activated")
	}
	call("app.test", 200)
	if e = f.Reload([]LabRoute{{Host: "app.test", Backend: "https://127.0.0.1:18087", TLSServerName: "api.test", TLSCAFile: "/missing-owned-ca.pem"}}); e == nil {
		t.Fatal("missing CA activated")
	}
	call("app.test", 200)
	next := []LabRoute{{Host: "alt.test", Backend: backend.URL}}
	if e = f.Reload(next); e != nil {
		t.Fatal(e)
	}
	call("app.test", 421)
	call("alt.test", 200)
	if e = f.Reload(original); e != nil {
		t.Fatal(e)
	}
	call("alt.test", 421)
	call("app.test", 200)
	if len(effects) != 5 {
		t.Fatal("rejected routes forwarded")
	}
	for _, host := range []string{"app.test", "app.test", "app.test", "alt.test", "app.test"} {
		if <-effects != host {
			t.Fatal("route effects changed")
		}
	}
	if !strings.HasPrefix(f.DataAddr, "127.0.0.1:") {
		t.Fatal("listener changed")
	}
	if e = f.Close(); e != nil {
		t.Fatal(e)
	}
	if e = f.Reload(original); e == nil {
		t.Fatal("closed proxy reloaded")
	}
}
