//go:build aegvium_transport_source

// SPDX-License-Identifier: BSD-3-Clause
package requestctx

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"net/netip"
	"time"

	"github.com/gonz0w/aegvium/internal/backendconfig"
)

type backendMaterials struct {
	configuration, certificatePEM, privateKeyPEM, clientRootDER []byte
	serverRoots                                                 map[[32]byte][]byte
}
type backendRoute struct {
	address netip.AddrPort
	config  *tls.Config
}
type backendSet struct {
	routes                     map[string]backendRoute
	client                     *x509.Certificate
	clientRoots, intermediates *x509.CertPool
	clientAnchor               [32]byte
	clientRole                 string
	forbidden                  map[string]bool
	serverRoles                map[string]bool
}

// newBackendSet is called only by actual fixed-file startup. It prepares owned
// explicit-root TLS configurations; it cannot dial, issue an allow or set Ready.
// Pure tests must never call this credential constructor.
func newBackendSet(pair *pairReceiver, descriptor []byte, m backendMaterials) (*backendSet, error) {
	if pair == nil || pair.owner == nil || pair.owner.snapshot == nil || pair.serverLeaf == nil {
		return nil, errPair
	}
	common := sha256.Sum256(descriptor)
	if !bytes.Equal(common[:], pair.owner.snapshot.tuple[40:72]) {
		return nil, errPair
	}
	c, e := backendconfig.Parse(m.configuration, descriptor)
	if e != nil || len(m.certificatePEM) < 1 || len(m.certificatePEM) > 65536 || len(m.privateKeyPEM) < 1 || len(m.privateKeyPEM) > 16384 || len(m.clientRootDER) < 1 || len(m.clientRootDER) > 16384 || sha256.Sum256(m.clientRootDER) != c.ClientAnchor || !certificateMaterial(m.certificatePEM, m.privateKeyPEM) {
		return nil, errPair
	}
	root, e := x509.ParseCertificate(bytes.Clone(m.clientRootDER))
	if e != nil {
		return nil, errPair
	}
	cert, e := tls.X509KeyPair(bytes.Clone(m.certificatePEM), bytes.Clone(m.privateKeyPEM))
	if e != nil || len(cert.Certificate) < 1 {
		return nil, errPair
	}
	leaf, e := x509.ParseCertificate(bytes.Clone(cert.Certificate[0]))
	if e != nil || !intendedUsage(leaf, x509.ExtKeyUsageClientAuth) || !hasLiteral(leaf.DNSNames, c.ClientRole) {
		return nil, errPair
	}
	a, e1 := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	b, e2 := x509.MarshalPKIXPublicKey(pair.serverLeaf.PublicKey)
	if e1 != nil || e2 != nil || bytes.Equal(a, b) {
		return nil, errPair
	} // Distinct I server/data keys.
	s := &backendSet{routes: make(map[string]backendRoute), client: leaf, clientRoots: x509.NewCertPool(), intermediates: x509.NewCertPool(), clientAnchor: c.ClientAnchor, clientRole: c.ClientRole, forbidden: make(map[string]bool), serverRoles: make(map[string]bool)}
	s.clientRoots.AddCert(root)
	s.forbidden[pair.owner.snapshot.serverName] = true
	for name := range pair.owner.snapshot.roles {
		s.forbidden[name] = true
	}
	for _, route := range pair.owner.snapshot.context.routes {
		s.forbidden[route.name] = true
	}
	for _, route := range c.Routes {
		s.forbidden[route.ServerName] = true
		s.serverRoles[route.ServerName] = true
	}
	for _, name := range leaf.DNSNames {
		if !dns(name) || s.forbidden[name] {
			return nil, errPair
		}
	}
	for _, raw := range cert.Certificate[1:] {
		chain, e := x509.ParseCertificate(bytes.Clone(raw))
		if e != nil {
			return nil, errPair
		}
		s.intermediates.AddCert(chain)
	}
	if !s.clientCurrent(time.Now()) {
		return nil, errPair
	}
	seen := make(map[[32]byte]bool)
	for _, entry := range c.Routes {
		raw := m.serverRoots[entry.ServerAnchor]
		if len(raw) < 1 || len(raw) > 16384 || sha256.Sum256(raw) != entry.ServerAnchor {
			return nil, errPair
		}
		serverRoot, e := x509.ParseCertificate(bytes.Clone(raw))
		if e != nil {
			return nil, errPair
		}
		pool := x509.NewCertPool()
		pool.AddCert(serverRoot)
		seen[entry.ServerAnchor] = true
		name, anchor := entry.ServerName, entry.ServerAnchor
		cfg := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{"http/1.1"}, RootCAs: pool, ServerName: name, Certificates: []tls.Certificate{cert}, SessionTicketsDisabled: true}
		cfg.VerifyConnection = func(state tls.ConnectionState) error {
			// Called by the future owning tls.Client handshake, never accepted as
			// a caller-supplied peer/permission or an already-completed request.
			if !s.clientCurrent(time.Now()) || state.Version != tls.VersionTLS13 || state.NegotiatedProtocol != "http/1.1" || state.DidResume || state.ServerName != name || len(state.PeerCertificates) < 1 || !intendedUsage(state.PeerCertificates[0], x509.ExtKeyUsageServerAuth) || !hasLiteral(state.PeerCertificates[0].DNSNames, name) {
				return errPair
			}
			for _, n := range state.PeerCertificates[0].DNSNames {
				if !dns(n) || n == s.clientRole || pair.owner.snapshot.roles[n] != nil || n == pair.owner.snapshot.serverName || n != name && s.serverRoles[n] {
					return errPair
				}
			}
			for _, chain := range state.VerifiedChains {
				if len(chain) > 0 && bytes.Equal(chain[0].Raw, state.PeerCertificates[0].Raw) && sha256.Sum256(chain[len(chain)-1].Raw) == anchor {
					if _, ok := chainValidity(chain, time.Now()); ok {
						return nil
					}
				}
			}
			return errPair
		}
		s.routes[entry.ID] = backendRoute{address: entry.Address, config: cfg}
	}
	if len(seen) != len(m.serverRoots) {
		return nil, errPair
	}
	return s, nil
}

func (s *backendSet) clientCurrent(now time.Time) bool {
	chains, e := s.client.Verify(x509.VerifyOptions{Roots: s.clientRoots, Intermediates: s.intermediates, DNSName: s.clientRole, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, CurrentTime: now})
	if e != nil {
		return false
	}
	for _, chain := range chains {
		if len(chain) > 0 && sha256.Sum256(chain[len(chain)-1].Raw) == s.clientAnchor {
			if _, ok := chainValidity(chain, now); ok {
				return true
			}
		}
	}
	return false
}
