// SPDX-License-Identifier: BSD-3-Clause
package spike

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/netip"
)

type labClientIdentityKey struct{}

func validLabClientIdentity(identity proxyIdentity, expected netip.AddrPort) bool {
	return expected.IsValid() && expected.Addr().Is4() && expected.Port() != 0 && identity.destination == expected && identity.source.IsValid() && identity.source.Addr().Is4() && identity.source.Port() != 0
}

// The caller asserts an externally enforced sender boundary. This does not
// authenticate a prefix or alter the connection's actual transport RemoteAddr.
func labClientContext(expected netip.AddrPort) func(context.Context, net.Conn) context.Context {
	return func(ctx context.Context, connection net.Conn) context.Context {
		// Never inherit another connection's identity from a caller base context.
		ctx = context.WithValue(ctx, labClientIdentityKey{}, proxyIdentity{})
		secure, ok := connection.(*tls.Conn)
		if !ok || secure == nil {
			return ctx
		}
		peer, ok := secure.NetConn().(*proxyV1Conn)
		if !ok || peer == nil || peer.Conn == nil || !validLabClientIdentity(peer.identity, expected) {
			return ctx
		}
		remote := peer.Conn.RemoteAddr()
		if remote == nil {
			return ctx
		}
		physical, err := netip.ParseAddrPort(remote.String())
		if err != nil || !physical.Addr().Is4() || !physical.Addr().IsLoopback() || physical.Port() == 0 {
			return ctx
		}
		return context.WithValue(ctx, labClientIdentityKey{}, peer.identity)
	}
}
func labClientIdentity(expected netip.AddrPort, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity, ok := r.Context().Value(labClientIdentityKey{}).(proxyIdentity)
		if !ok || !validLabClientIdentity(identity, expected) {
			w.Header().Set("Connection", "close")
			http.Error(w, "client identity unavailable", http.StatusServiceUnavailable)
			return
		}
		// The server body populates the original request's Trailer map at EOF.
		// Allocate before the shallow request copy so undeclared trailer keys
		// remain visible to the downstream admission check as well.
		if r.Trailer == nil {
			r.Trailer = make(http.Header)
		}
		copy := r.WithContext(r.Context())
		copy.RemoteAddr = identity.source.String()
		next.ServeHTTP(w, copy)
	})
}
