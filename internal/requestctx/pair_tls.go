//go:build aegvium_transport_source

// SPDX-License-Identifier: BSD-3-Clause
package requestctx

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"sync"
	"time"
)

// No default provider/caller. Actual credential parsing and TLS execution remain
// unqualified and unrun; the source tag is not operational enablement.
type pairMaterials struct {
	descriptor, certificatePEM, privateKeyPEM, serverRootDER []byte
	clientRootDER                                            [][]byte
}
type pairReceiver struct {
	owner                            *pairControlOwner
	config                           *tls.Config
	serverLeaf                       *x509.Certificate
	serverRoots, serverIntermediates *x509.CertPool
}
type pairOutcome struct {
	Code                              int
	PreparedWritten, Closed, Retained bool
}

var pairStartup struct {
	sync.Mutex
	attempted bool
}

func hasLiteral(names []string, want string) bool {
	for _, s := range names {
		if s == want {
			return true
		}
	}
	return false
}
func intendedUsage(c *x509.Certificate, usage x509.ExtKeyUsage) bool {
	return c != nil && !c.IsCA && len(c.ExtKeyUsage) == 1 && c.ExtKeyUsage[0] == usage && len(c.UnknownExtKeyUsage) == 0
}
func certificateMaterial(cert, key []byte) bool {
	begins := bytes.Count(cert, []byte("-----BEGIN "))
	if begins < 1 || begins > 8 {
		return false
	}
	count := 0
	for len(bytes.TrimSpace(cert)) != 0 {
		cert = bytes.TrimSpace(cert)
		if !bytes.HasPrefix(cert, []byte("-----BEGIN CERTIFICATE-----")) {
			return false
		}
		b, rest := pem.Decode(cert)
		if b == nil || b.Type != "CERTIFICATE" || len(b.Headers) != 0 {
			return false
		}
		count++
		cert = rest
	}
	if count != begins || bytes.Count(key, []byte("-----BEGIN ")) != 1 {
		return false
	}
	key = bytes.TrimSpace(key)
	b, rest := pem.Decode(key)
	return b != nil && bytes.HasPrefix(key, []byte("-----BEGIN "+b.Type+"-----")) && len(bytes.TrimSpace(rest)) == 0 && len(b.Headers) == 0 && (b.Type == "PRIVATE KEY" || b.Type == "RSA PRIVATE KEY" || b.Type == "EC PRIVATE KEY")
}
func newPairReceiver(input pairMaterials) (*pairReceiver, error) {
	pairStartup.Lock()
	if pairStartup.attempted {
		pairStartup.Unlock()
		return nil, errPair
	}
	pairStartup.attempted = true
	pairStartup.Unlock()
	if len(input.descriptor) < 1 || len(input.descriptor) > 8192 || len(input.certificatePEM) < 1 || len(input.certificatePEM) > 65536 || len(input.privateKeyPEM) < 1 || len(input.privateKeyPEM) > 16384 || len(input.serverRootDER) < 1 || len(input.serverRootDER) > 16384 || len(input.clientRootDER) < 1 || len(input.clientRootDER) > 8 {
		return nil, errPair
	}
	s, err := newPairedSnapshot(bytes.Clone(input.descriptor))
	if err != nil {
		return nil, errPair
	}
	serverDER := bytes.Clone(input.serverRootDER)
	if sha256.Sum256(serverDER) != s.serverAnchor {
		return nil, errPair
	}
	serverRoot, err := x509.ParseCertificate(serverDER)
	if err != nil {
		return nil, errPair
	}
	serverRoots := x509.NewCertPool()
	serverRoots.AddCert(serverRoot)
	frontRoots := x509.NewCertPool()
	seen := make(map[[32]byte]bool)
	for _, raw := range input.clientRootDER {
		if len(raw) < 1 || len(raw) > 16384 {
			return nil, errPair
		}
		der := bytes.Clone(raw)
		pin := sha256.Sum256(der)
		if seen[pin] || !s.anchors[pin] {
			return nil, errPair
		}
		root, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, errPair
		}
		seen[pin] = true
		frontRoots.AddCert(root)
	}
	if len(seen) != len(s.anchors) {
		return nil, errPair
	}
	certBytes, keyBytes := bytes.Clone(input.certificatePEM), bytes.Clone(input.privateKeyPEM)
	if !certificateMaterial(certBytes, keyBytes) {
		return nil, errPair
	}
	cert, err := tls.X509KeyPair(certBytes, keyBytes)
	if err != nil || len(cert.Certificate) == 0 {
		return nil, errPair
	}
	leaf, err := x509.ParseCertificate(bytes.Clone(cert.Certificate[0]))
	if err != nil || !intendedUsage(leaf, x509.ExtKeyUsageServerAuth) || !hasLiteral(leaf.DNSNames, s.serverName) {
		return nil, errPair
	}
	for _, name := range leaf.DNSNames {
		if !dns(name) || s.roles[name] != nil {
			return nil, errPair
		}
	}
	intermediates := x509.NewCertPool()
	for _, der := range cert.Certificate[1:] {
		c, err := x509.ParseCertificate(bytes.Clone(der))
		if err != nil {
			return nil, errPair
		}
		intermediates.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: serverRoots, Intermediates: intermediates, DNSName: s.serverName, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, CurrentTime: time.Now()}); err != nil {
		return nil, errPair
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{"http/1.1"}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: frontRoots, Certificates: []tls.Certificate{cert}, SessionTicketsDisabled: true}
	r := &pairReceiver{owner: &pairControlOwner{snapshot: s}, config: cfg, serverLeaf: leaf, serverRoots: serverRoots, serverIntermediates: intermediates}
	if _, ok := r.serverValidity(time.Now()); !ok {
		return nil, errPair
	}
	return r, nil
}
func (r *pairReceiver) reserve(ctx context.Context) (*pairReservation, error) {
	if r == nil || r.owner == nil {
		return nil, errPair
	}
	return r.owner.reserve(ctx)
}

type pairValidity struct{ from, until time.Time }

func (v pairValidity) current(now time.Time) bool {
	return !now.Before(v.from) && now.Before(v.until)
}
func chainValidity(chain []*x509.Certificate, now time.Time) (pairValidity, bool) {
	if len(chain) == 0 {
		return pairValidity{}, false
	}
	var v pairValidity
	for i, cert := range chain {
		if cert == nil {
			return pairValidity{}, false
		}
		if i == 0 || cert.NotBefore.After(v.from) {
			v.from = cert.NotBefore
		}
		if i == 0 || cert.NotAfter.Before(v.until) {
			v.until = cert.NotAfter
		}
	}
	return v, v.current(now)
}
func (r *pairReceiver) serverValidity(now time.Time) (pairValidity, bool) {
	if r == nil || r.serverLeaf == nil || r.serverRoots == nil || r.serverIntermediates == nil {
		return pairValidity{}, false
	}
	chains, err := r.serverLeaf.Verify(x509.VerifyOptions{Roots: r.serverRoots, Intermediates: r.serverIntermediates, DNSName: r.owner.snapshot.serverName, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, CurrentTime: now})
	if err != nil {
		return pairValidity{}, false
	}
	for _, chain := range chains {
		if len(chain) == 0 || sha256.Sum256(chain[len(chain)-1].Raw) != r.owner.snapshot.serverAnchor {
			continue
		}
		if v, ok := chainValidity(chain, now); ok {
			return v, true
		}
	}
	return pairValidity{}, false
}
func (r *pairReceiver) frontendRole(c *tls.Conn, now time.Time) (string, pairValidity, bool) {
	state := c.ConnectionState() // ONLY the same receiver-owned completed Conn.
	if !state.HandshakeComplete || state.Version != tls.VersionTLS13 || state.NegotiatedProtocol != "http/1.1" || state.DidResume || state.ServerName != r.owner.snapshot.serverName || len(state.PeerCertificates) == 0 || len(state.VerifiedChains) == 0 {
		return "", pairValidity{}, false
	}
	leaf := state.PeerCertificates[0]
	if !intendedUsage(leaf, x509.ExtKeyUsageClientAuth) {
		return "", pairValidity{}, false
	}
	role := ""
	for _, name := range leaf.DNSNames {
		if !dns(name) || name == r.owner.snapshot.serverName {
			return "", pairValidity{}, false
		}
		if r.owner.snapshot.roles[name] != nil {
			if role != "" {
				return "", pairValidity{}, false
			}
			role = name
		}
	}
	if role == "" {
		return "", pairValidity{}, false
	}
	for _, chain := range state.VerifiedChains {
		if len(chain) == 0 || !bytes.Equal(chain[0].Raw, leaf.Raw) {
			continue
		}
		anchor := sha256.Sum256(chain[len(chain)-1].Raw)
		if !r.owner.snapshot.roles[role][anchor] {
			continue
		}
		if v, ok := chainValidity(chain, now); ok {
			return role, v, true
		}
	}
	return "", pairValidity{}, false
}
func (r *pairReceiver) frontend(c *tls.Conn, now time.Time) (pairValidity, bool) {
	_, window, ok := r.frontendRole(c, now)
	return window, ok
}
func earlier(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// Owns and parses ONE control request from its OWN tls.Conn. No callable Peer
// constructor or RecordAuthenticated(peer, arbitraryRequest) exists.
func (r *pairReceiver) serve(res *pairReservation, raw net.Conn) (out pairOutcome) {
	out.Retained = true
	if r == nil || r.owner == nil || res == nil || res.state == nil || res.state.owner != r.owner {
		return
	}
	e, err := res.bind(raw)
	if err != nil {
		return
	}
	s := res.state
	returned := false
	defer func() {
		if !returned {
			_ = recover()
			e.poison()
		}
		_ = e.Close() // Single raw-close owner also receives TLS-internal Close.
		s.finish()
		r.owner.mu.Lock()
		out.Closed = e.closeReturned && e.closeOK && !e.uncertain && e.active == 0
		out.Retained = !s.released
		r.owner.mu.Unlock()
	}()
	func() {
		ctx, cancel := context.WithDeadline(s.parent, s.total)
		defer cancel()
		r.owner.mu.Lock()
		eligible := !r.owner.retired
		r.owner.mu.Unlock()
		_, serverOK := r.serverValidity(time.Now())
		if !eligible || ctx.Err() != nil || !serverOK || !time.Now().Before(s.total) {
			return
		}
		handshakeUntil := earlier(s.total, time.Now().Add(time.Second))
		if e.SetDeadline(handshakeUntil) != nil {
			return
		}
		conn := tls.Server(e, r.config.Clone())
		handshakeCtx, stopHandshake := context.WithDeadline(ctx, handshakeUntil)
		err = conn.HandshakeContext(handshakeCtx)
		handshakeOK := err == nil && handshakeCtx.Err() == nil && time.Now().Before(handshakeUntil)
		stopHandshake()
		_, frontendOK := r.frontend(conn, time.Now())
		if !handshakeOK || !frontendOK {
			return
		}
		readUntil := earlier(s.total, time.Now().Add(time.Second))
		if e.SetDeadline(readUntil) != nil {
			return
		}
		header, ok := readPairHeader(ctx, readUntil, conn)
		code := 400
		if ok {
			var body [104]byte
			if readPairExact(ctx, readUntil, conn, body[:]) {
				code = pairHTTPStatus(r.owner.snapshot, header, body[:])
			}
		}
		if e.SetDeadline(s.total) != nil {
			return
		}
		now := time.Now()
		serverWindow, serverOK := r.serverValidity(now)
		clientWindow, frontendOK := r.frontend(conn, now)
		r.owner.mu.Lock()
		now = time.Now()
		eligible = !r.owner.retired && ctx.Err() == nil && now.Before(s.total) && serverOK && frontendOK && serverWindow.current(now) && clientWindow.current(now)
		r.owner.mu.Unlock()
		if !eligible {
			return
		} // Response start barrier; later retire cannot undo I/O.
		out.Code = code
		if writePairExact(ctx, s.total, conn, pairResponse(r.owner.snapshot, code)) {
			out.PreparedWritten = code == 200
		}
	}()
	returned = true
	return
}
