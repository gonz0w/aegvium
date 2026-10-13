// SPDX-License-Identifier: BSD-3-Clause
package spike

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/corazawaf/coraza/v3"
	corazahttp "github.com/corazawaf/coraza/v3/http"
)

type wiringEvent struct {
	Phase   uint64
	Request string
	Role    string
	Status  int
}
type wiringFixture struct {
	mu            sync.Mutex
	phase         uint64
	active        int
	terminal      bool
	healthFault   string
	healthClosed  bool
	healthClosing bool
	healthWorkers sync.WaitGroup
	events        []wiringEvent
	seen          map[string]bool
	sinkSeen      map[string]bool
	closeOnce     sync.Once
	closeErr      error
	engine        atomic.Bool
	receiver      *proxyV1Listener
	listeners     []net.Listener
	servers       []*http.Server
	done          []chan error
	transport     *http.Transport
}

// Test-only owned loopback roles: sink, data, health. Zero ports are host fixtures.
func startWiringFixture(expected netip.AddrPort, ports [3]uint16) (*wiringFixture, error) {
	f := &wiringFixture{seen: make(map[string]bool), sinkSeen: make(map[string]bool)}
	for _, port := range ports {
		listener, err := net.Listen("tcp4", "127.0.0.1:"+strconv.Itoa(int(port)))
		if err != nil {
			for _, l := range f.listeners {
				_ = l.Close()
			}
			return nil, err
		}
		f.listeners = append(f.listeners, listener)
	}
	receiver, err := newProxyV1Listener(f.listeners[1], expected, time.Second, 2, &f.engine)
	if err != nil {
		for _, l := range f.listeners {
			_ = l.Close()
		}
		return nil, err
	}
	f.receiver = receiver
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(rules))
	if err != nil {
		_ = receiver.Close()
		for _, l := range f.listeners {
			_ = l.Close()
		}
		return nil, err
	}
	f.transport = &http.Transport{Proxy: nil, DisableKeepAlives: true, DialContext: (&net.Dialer{Timeout: time.Second}).DialContext}
	client := &http.Client{Transport: f.transport, Timeout: time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	sink := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		phase, id, valid := wiringIdentity(r)
		f.mu.Lock()
		defer f.mu.Unlock()
		key := strconv.FormatUint(phase, 10) + "/" + id
		if !valid || (id != "benign" && id != "window" && id != "witness") || !f.seen[key] || f.sinkSeen[key] || f.active == 0 || r.Method != "GET" || r.URL.RequestURI() != "/allowed" || phase != f.phase || len(f.events) >= 64 {
			w.WriteHeader(400)
			return
		}
		f.sinkSeen[key] = true
		f.events = append(f.events, wiringEvent{phase, id, "sink", 200})
		_, _ = io.WriteString(w, "synthetic sink\n")
	})
	forward := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		request, e := http.NewRequestWithContext(r.Context(), "GET", "http://"+f.listeners[0].Addr().String()+"/allowed", nil)
		if e != nil {
			w.WriteHeader(502)
			return
		}
		request.Header.Set("X-Aegvium-Phase", r.Header.Get("X-Aegvium-Phase"))
		request.Header.Set("X-Aegvium-Request", r.Header.Get("X-Aegvium-Request"))
		response, e := client.Do(request)
		if e != nil {
			w.WriteHeader(502)
			return
		}
		defer response.Body.Close()
		body, e := io.ReadAll(io.LimitReader(response.Body, 32))
		if e != nil || response.StatusCode != 200 || string(body) != "synthetic sink\n" {
			w.WriteHeader(502)
			return
		}
		_, _ = w.Write(body)
	})
	inspect := corazahttp.WrapHandler(waf, forward)
	data := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "close")
		phase, id, valid := wiringIdentity(r)
		f.mu.Lock()
		key := strconv.FormatUint(phase, 10) + "/" + id
		if !valid || phase != f.phase || !f.engine.Load() || f.terminal || r.Method != "GET" || (((id != "benign" && id != "window" && id != "witness") || r.URL.RequestURI() != "/allowed") && (id != "denied" || r.URL.RequestURI() != "/forbidden")) || r.ContentLength != 0 || len(r.TransferEncoding) != 0 || f.seen[key] || len(f.seen) >= 32 || len(f.events)+2*f.active >= 62 {
			f.mu.Unlock()
			w.WriteHeader(400)
			return
		}
		f.seen[key] = true
		f.active++
		f.mu.Unlock()
		recorder := &wiringResponse{ResponseWriter: w, status: 200}
		inspect.ServeHTTP(recorder, r)
		f.mu.Lock()
		f.events = append(f.events, wiringEvent{phase, id, "inspection", recorder.status})
		f.active--
		f.mu.Unlock()
	})
	handlers := []http.Handler{sink, data, f.healthHandler()}
	for i, handler := range handlers {
		server := &http.Server{Handler: handler, ReadHeaderTimeout: time.Second, ReadTimeout: 2 * time.Second, WriteTimeout: 2 * time.Second, IdleTimeout: time.Second, MaxHeaderBytes: 4096}
		listener := f.listeners[i]
		if i == 1 {
			listener = receiver
		}
		done := make(chan error, 1)
		f.servers = append(f.servers, server)
		f.done = append(f.done, done)
		go func() { done <- server.Serve(listener) }()
	}
	return f, nil
}

type wiringResponse struct {
	http.ResponseWriter
	status int
}

func (w *wiringResponse) WriteHeader(code int) { w.status = code; w.ResponseWriter.WriteHeader(code) }
func wiringIdentity(r *http.Request) (uint64, string, bool) {
	phase, e := strconv.ParseUint(r.Header.Get("X-Aegvium-Phase"), 10, 64)
	id := r.Header.Get("X-Aegvium-Request")
	return phase, id, e == nil && phase > 0 && phase <= 16 && (id == "benign" || id == "denied" || id == "window" || id == "witness")
}

func (f *wiringFixture) apply(phase uint64, operation string) error {
	f.mu.Lock()
	if phase <= f.phase || phase > 16 || f.active != 0 || f.terminal || (!wiringOperation(operation) || operation == "stop" || (f.healthClosed && operation != "close")) {
		f.mu.Unlock()
		return errors.New("invalid/stale/busy/terminal phase")
	}
	f.phase = phase
	f.engine.Store(operation == "ready" || strings.HasPrefix(operation, "health-"))
	f.healthFault = operation
	if operation == "health-refused" {
		f.healthClosed = true
	}
	f.terminal = operation == "close"
	f.mu.Unlock()
	if operation == "health-refused" {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := f.servers[2].Shutdown(ctx); err != nil {
			return err
		}
		select {
		case err := <-f.done[2]:
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				return err
			}
		case <-time.After(time.Second):
			return errors.New("refused health server did not join")
		}
		f.done[2] = nil
	}
	if operation == "close" {
		return f.receiver.Close()
	}
	return nil
}
func (f *wiringFixture) snapshot() []wiringEvent {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]wiringEvent(nil), f.events...)
}
func (f *wiringFixture) close() error {
	f.closeOnce.Do(func() { f.closeErr = f.shutdown() })
	return f.closeErr
}
func (f *wiringFixture) shutdown() error {
	f.mu.Lock()
	f.engine.Store(false)
	f.terminal = true
	f.healthClosing = true
	f.mu.Unlock()
	var result error
	if e := f.receiver.Close(); e != nil {
		result = e
	}
	for _, s := range f.servers {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		if e := s.Shutdown(ctx); e != nil {
			result = e
			_ = s.Close()
		}
		cancel()
	}
	for _, done := range f.done {
		if done == nil {
			continue
		}
		select {
		case e := <-done:
			if e != nil && !errors.Is(e, http.ErrServerClosed) && !errors.Is(e, net.ErrClosed) {
				result = e
			}
		case <-time.After(time.Second):
			result = errors.New("server did not join")
		}
	}
	joined := make(chan struct{})
	go func() { f.healthWorkers.Wait(); close(joined) }()
	select {
	case <-joined:
	case <-time.After(3 * time.Second):
		result = errors.New("health workers did not join")
	}
	f.transport.CloseIdleConnections()
	return result
}

// Faults affect only the owned health role. The receiver remains synthetically ready.
func wiringOperation(operation string) bool {
	switch operation {
	case "down", "ready", "close", "stop", "health-silent", "health-malformed", "health-redirect", "health-refused":
		return true
	}
	return false
}
func (f *wiringFixture) healthHandler() http.Handler {
	normal := proxyReadyHandler(f.receiver)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		if f.healthClosing {
			f.mu.Unlock()
			w.WriteHeader(503)
			return
		}
		mode := f.healthFault
		f.healthWorkers.Add(1)
		f.mu.Unlock()
		defer f.healthWorkers.Done()
		if r.Method != "HEAD" || r.URL.RequestURI() != "/ready" {
			w.WriteHeader(400)
			return
		}
		switch mode {
		case "health-silent":
			// Request parsing is complete, but no bytes arrive within readycheck's 200ms budget.
			select {
			case <-r.Context().Done():
				return
			case <-time.After(time.Second):
				w.WriteHeader(503)
			}
		case "health-malformed":
			c, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				return
			}
			defer c.Close()
			_ = c.SetWriteDeadline(time.Now().Add(time.Second))
			_, _ = io.WriteString(c, "malformed health\r\n\r\n")
		case "health-redirect":
			w.Header().Set("Location", "http://127.0.0.1:18085/ready")
			w.WriteHeader(302)
		default:
			normal.ServeHTTP(w, r)
		}
	})
}
