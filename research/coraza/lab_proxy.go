// SPDX-License-Identifier: BSD-3-Clause
package spike

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	crs "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
	corazahttp "github.com/corazawaf/coraza/v3/http"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const labDirectives = "Include @coraza.conf-recommended\nSecRuleEngine On\nInclude @crs-setup.conf.example\nInclude @owasp_crs/*.conf\n"
const LabBodyLimit = 4096

// LabProfile is test instrumentation, not a supported product configuration API.
type LabProfile struct {
	DataAddress, HealthAddress string
	Routes                     []LabRoute
	Ingress                    netip.AddrPort
	FrontendCertificate        *tls.Certificate
}
type LabProxy struct {
	DataAddr, HealthAddr string
	receiver             *proxyV1Listener
	servers              []*http.Server
	done                 []chan error
	routes               *labRouteOwner
	engine               atomic.Bool
	once                 sync.Once
	closeErr             error
	frontend             *tls.Certificate
}

func labAddress(value string, zero bool) bool {
	a, e := netip.ParseAddrPort(value)
	return e == nil && a.Addr() == netip.MustParseAddr("127.0.0.1") && (zero || a.Port() != 0)
}
func stripLabHeaders(h http.Header) {
	for k := range h {
		l := strings.ToLower(k)
		if l == "forwarded" || strings.HasPrefix(l, "x-forwarded-") || l == "x-real-ip" || l == "x-original-url" || l == "x-rewrite-url" || strings.HasPrefix(l, "proxy-") {
			h.Del(k)
		}
	}
}
func labHandler(backend string, directives string) (http.Handler, *http.Transport, io.Closer, error) {
	h, transports, closer, e := labConfiguredHandler([]LabRoute{{Host: "app.test", Backend: "http://" + backend}}, directives)
	if e != nil {
		return nil, nil, nil, e
	}
	return h, transports[0], closer, nil
}
func labConfiguredHandler(routes []LabRoute, directives string) (http.Handler, []*http.Transport, io.Closer, error) {
	if len(routes) < 1 || len(routes) > 8 {
		return nil, nil, nil, errors.New("lab route bound")
	}
	type prepared struct{ proxy *httputil.ReverseProxy }
	var transports []*http.Transport
	table := map[string]prepared{}
	cleanup := func() {
		for _, tr := range transports {
			tr.CloseIdleConnections()
		}
	}
	for _, route := range routes {
		if !labName(route.Host) {
			cleanup()
			return nil, nil, nil, errors.New("invalid lab host")
		}
		if _, ok := table[route.Host]; ok {
			cleanup()
			return nil, nil, nil, errors.New("duplicate lab host")
		}
		target, tlsConfig, e := labRouteTarget(route)
		if e != nil {
			cleanup()
			return nil, nil, nil, e
		}
		tr := &http.Transport{Proxy: nil, DisableKeepAlives: true, MaxConnsPerHost: 4, DialContext: (&net.Dialer{Timeout: time.Second}).DialContext, ResponseHeaderTimeout: time.Second, TLSHandshakeTimeout: time.Second, TLSClientConfig: tlsConfig}
		transports = append(transports, tr)
		proxy := &httputil.ReverseProxy{Rewrite: func(p *httputil.ProxyRequest) {
			p.SetURL(target)
			p.Out.Host = route.Host
			stripLabHeaders(p.Out.Header)
		}, Transport: tr, ErrorLog: log.New(io.Discard, "", 0), ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) { http.Error(w, "backend unavailable", 502) }, ModifyResponse: func(r *http.Response) error {
			defer r.Body.Close()
			data, e := io.ReadAll(io.LimitReader(r.Body, LabBodyLimit+1))
			if e != nil || len(data) > LabBodyLimit {
				return errors.New("lab response bound")
			}
			r.Body = io.NopCloser(bytes.NewReader(data))
			return nil
		}}
		table[route.Host] = prepared{proxy}
	}
	waf, e := coraza.NewWAF(coraza.NewWAFConfig().WithRootFS(crs.FS).WithDirectives(directives))
	if e != nil {
		cleanup()
		return nil, nil, nil, e
	}
	handlers := map[string]http.Handler{}
	for host, route := range table {
		handlers[host] = corazahttp.WrapHandler(waf, route.proxy)
		handlers[host+":18120"] = handlers[host]
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "close")
		inspect, ok := handlers[r.Host]
		if !ok {
			http.Error(w, "unknown host", 421)
			return
		}
		if r.ProtoMajor != 1 || r.ProtoMinor != 1 || r.URL.IsAbs() || r.URL.Host != "" {
			http.Error(w, "unsupported request", 400)
			return
		}
		if r.Method != "GET" && r.Method != "HEAD" && r.Method != "POST" {
			http.Error(w, "unsupported method", 405)
			return
		}
		if r.Header.Get("Upgrade") != "" || strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") {
			http.Error(w, "upgrade unsupported", 501)
			return
		}
		original := r.Body
		if original == nil {
			original = http.NoBody
		}
		defer original.Close()
		if r.ContentLength > LabBodyLimit {
			http.Error(w, "body too large", 413)
			return
		}
		if r.Method != "POST" && (r.ContentLength != 0 || len(r.TransferEncoding) > 0) {
			http.Error(w, "body unsupported", 400)
			return
		}
		if r.Method == "POST" {
			values := r.Header.Values("Content-Type")
			if len(values) != 1 {
				http.Error(w, "media unsupported", 415)
				return
			}
			kind, params, e := mime.ParseMediaType(values[0])
			if e != nil || (kind != "application/json" && kind != "application/x-www-form-urlencoded") {
				http.Error(w, "media unsupported", 415)
				return
			}
			for k, v := range params {
				if k != "charset" || !strings.EqualFold(v, "utf-8") {
					http.Error(w, "media unsupported", 415)
					return
				}
			}
		}
		enc := r.Header.Values("Content-Encoding")
		if len(enc) > 1 || (len(enc) == 1 && !strings.EqualFold(enc[0], "identity")) {
			http.Error(w, "encoding unsupported", 415)
			return
		}
		data, e := io.ReadAll(io.LimitReader(original, LabBodyLimit+1))
		if len(data) > LabBodyLimit {
			http.Error(w, "body too large", 413)
			return
		}
		if e != nil {
			http.Error(w, "body unavailable", 500)
			return
		}
		if r.ContentLength >= 0 && r.ContentLength != int64(len(data)) {
			http.Error(w, "length mismatch", 400)
			return
		}
		stripLabHeaders(r.Header)
		r.Body = io.NopCloser(bytes.NewReader(data))
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		inspect.ServeHTTP(w, r.WithContext(ctx))
	}), transports, waf.(io.Closer), nil
}

func StartLabProxy(p LabProfile) (*LabProxy, error) { return startLabProxy(p, labDirectives) }
func startLabProxy(p LabProfile, directives string) (*LabProxy, error) {
	if !labAddress(p.DataAddress, true) || !labAddress(p.HealthAddress, true) || !p.Ingress.IsValid() || p.Ingress.Addr() != netip.MustParseAddr("127.0.0.1") || p.Ingress.Port() == 0 {
		return nil, errors.New("invalid owned lab endpoints")
	}
	frontend, e := labFrontendCertificate(p.FrontendCertificate, p.Routes)
	if e != nil {
		return nil, e
	}
	generation, e := prepareLabRoutes(p.Routes, directives)
	if e != nil {
		return nil, e
	}
	data, e := net.Listen("tcp4", p.DataAddress)
	if e != nil {
		_ = generation.close()
		return nil, e
	}
	health, e := net.Listen("tcp4", p.HealthAddress)
	if e != nil {
		data.Close()
		_ = generation.close()
		return nil, e
	}
	f := &LabProxy{DataAddr: data.Addr().String(), HealthAddr: health.Addr().String(), routes: &labRouteOwner{active: generation}, frontend: frontend}
	f.engine.Store(true)
	f.receiver, e = newProxyV1Listener(&labLimitedListener{Listener: data}, p.Ingress, time.Second, 2, &f.engine)
	if e != nil {
		data.Close()
		health.Close()
		_ = generation.close()
		return nil, e
	}
	var application http.Handler = labAdmission(f.routes)
	if frontend != nil {
		application = labTLSAuthority(application)
	}
	for i, h := range []http.Handler{application, proxyReadyHandler(f.receiver)} {
		server := &http.Server{Handler: h, ReadHeaderTimeout: time.Second, ReadTimeout: 2 * time.Second, WriteTimeout: 4 * time.Second, IdleTimeout: time.Second, MaxHeaderBytes: 4096, ErrorLog: log.New(io.Discard, "", 0)}
		var listener net.Listener = f.receiver
		if i == 0 && frontend != nil {
			listener = tls.NewListener(listener, f.frontendTLS())
		}
		if i == 1 {
			listener = health
		}
		done := make(chan error, 1)
		f.servers = append(f.servers, server)
		f.done = append(f.done, done)
		go func() { done <- server.Serve(listener) }()
	}
	return f, nil
}
func (f *LabProxy) Close() error {
	f.once.Do(func() {
		f.engine.Store(false)
		_ = f.receiver.Close()
		f.routes.stopReloads()
		for _, s := range f.servers {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			if e := s.Shutdown(ctx); e != nil {
				f.closeErr = e
				_ = s.Close()
			}
			cancel()
		}
		for _, done := range f.done {
			select {
			case e := <-done:
				if e != nil && !errors.Is(e, http.ErrServerClosed) && !errors.Is(e, net.ErrClosed) {
					f.closeErr = e
				}
			case <-time.After(time.Second):
				f.closeErr = errors.New("lab server did not join")
			}
		}
		if f.closeErr == nil {
			f.closeErr = f.routes.close()
		}
	})
	return f.closeErr
}

type labLimitedListener struct {
	net.Listener
	active atomic.Int64
}
type labLimitedConn struct {
	net.Conn
	owner *labLimitedListener
	once  sync.Once
}

func (l *labLimitedListener) Accept() (net.Conn, error) {
	for {
		c, e := l.Listener.Accept()
		if e != nil {
			return nil, e
		}
		if l.active.Add(1) > 8 {
			l.active.Add(-1)
			c.Close()
			continue
		}
		return &labLimitedConn{Conn: c, owner: l}, nil
	}
}
func (c *labLimitedConn) Close() error {
	e := c.Conn.Close()
	c.once.Do(func() { c.owner.active.Add(-1) })
	return e
}
