// SPDX-License-Identifier: BSD-3-Clause
package spike

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
)

// ErrLabReloadCleanup means activation occurred, but retiring the old generation
// failed. The caller must shut down instead of reporting an uncommitted rejection.
var ErrLabReloadCleanup = errors.New("lab reload retirement failed")

type labRouteGeneration struct {
	handler    http.Handler
	transports []interface{ CloseIdleConnections() }
	waf        io.Closer
	once       sync.Once
	closeErr   error
}

func prepareLabRoutes(routes []LabRoute, directives string) (*labRouteGeneration, error) {
	handler, transports, waf, e := labConfiguredHandler(routes, directives)
	if e != nil {
		return nil, e
	}
	generation := &labRouteGeneration{handler: handler, waf: waf}
	for _, transport := range transports {
		generation.transports = append(generation.transports, transport)
	}
	return generation, nil
}
func (g *labRouteGeneration) close() error {
	g.once.Do(func() {
		for _, transport := range g.transports {
			transport.CloseIdleConnections()
		}
		g.closeErr = g.waf.Close()
	})
	return g.closeErr
}

type labRouteOwner struct {
	mu       sync.RWMutex
	change   sync.Mutex
	active   *labRouteGeneration
	closed   bool
	stopping bool
}

func (o *labRouteOwner) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	o.mu.RLock()
	defer o.mu.RUnlock()
	if o.closed {
		http.Error(w, "inspection unavailable", 503)
		return
	}
	o.active.handler.ServeHTTP(w, r)
}
func (o *labRouteOwner) replace(next *labRouteGeneration) error {
	o.change.Lock()
	defer o.change.Unlock()
	o.mu.Lock()
	if o.closed || o.stopping {
		o.mu.Unlock()
		return errors.Join(errors.New("lab route owner closed"), next.close())
	}
	old := o.active
	o.active = next
	o.mu.Unlock()
	if e := old.close(); e != nil {
		return fmt.Errorf("%w: %v", ErrLabReloadCleanup, e)
	}
	return nil
}
func (o *labRouteOwner) stopReloads() { o.change.Lock(); o.stopping = true; o.change.Unlock() }
func (o *labRouteOwner) close() error {
	o.change.Lock()
	defer o.change.Unlock()
	o.mu.Lock()
	if o.closed {
		o.mu.Unlock()
		return nil
	}
	o.stopping = true
	o.closed = true
	old := o.active
	o.active = nil
	o.mu.Unlock()
	return old.close()
}

// Reload replaces owned lab routes; it does not update embedded rules or bind
// new listeners. Failed preparation preserves the currently serving generation.
func (f *LabProxy) Reload(routes []LabRoute) error { return f.reload(routes, labDirectives) }
func (f *LabProxy) reload(routes []LabRoute, directives string) error {
	next, e := prepareLabRoutes(routes, directives)
	if e != nil {
		return e
	}
	return f.routes.replace(next)
}
