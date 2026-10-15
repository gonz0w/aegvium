// SPDX-License-Identifier: BSD-3-Clause
package spike

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"strings"
)

// ReadLabCertificate reads startup-only owned inputs. No key bytes enter receipts.
func ReadLabCertificate(certFile, keyFile string) (*tls.Certificate, error) {
	certPEM, e := ReadLabFile(certFile, 65536)
	if e != nil {
		return nil, e
	}
	keyPEM, e := ReadLabFile(keyFile, 65536)
	if e != nil {
		return nil, e
	}
	cert, e := tls.X509KeyPair(certPEM, keyPEM)
	if e != nil {
		return nil, errors.New("invalid lab frontend keypair")
	}
	return &cert, nil
}

func labFrontendCertificate(input *tls.Certificate, routes []LabRoute) (*tls.Certificate, error) {
	if input == nil {
		return nil, nil
	}
	// Reparse the public chain and copy its bytes rather than trusting caller Leaf.
	if len(input.Certificate) == 0 || input.PrivateKey == nil {
		return nil, errors.New("incomplete lab frontend certificate")
	}
	cert := *input
	cert.Certificate = make([][]byte, len(input.Certificate))
	for i, raw := range input.Certificate {
		cert.Certificate[i] = append([]byte(nil), raw...)
	}
	leaf, e := x509.ParseCertificate(cert.Certificate[0])
	if e != nil {
		return nil, errors.New("invalid lab frontend certificate")
	}
	cert.Leaf = leaf
	for _, route := range routes {
		if !labName(route.Host) || leaf.VerifyHostname(route.Host) != nil {
			return nil, errors.New("lab frontend certificate route coverage")
		}
	}
	return &cert, nil
}

func (f *LabProxy) frontendTLS() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}, SessionTicketsDisabled: true,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			f.routes.mu.RLock()
			defer f.routes.mu.RUnlock()
			if !labName(hello.ServerName) || f.routes.closed || !f.routes.active.hosts[hello.ServerName] || f.frontend.Leaf.VerifyHostname(hello.ServerName) != nil {
				return nil, errors.New("lab frontend name rejected")
			}
			return f.frontend, nil
		},
	}
}

func labTLSAuthority(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := strings.TrimSuffix(r.Host, ":18120")
		if r.TLS == nil || !r.TLS.HandshakeComplete || !labName(r.TLS.ServerName) || host != r.TLS.ServerName {
			w.Header().Set("Connection", "close")
			http.Error(w, "authority rejected", http.StatusMisdirectedRequest)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// CheckLabFrontend performs the same certificate coverage admission without bind.
func CheckLabFrontend(p LabProfile) error {
	_, e := labFrontendCertificate(p.FrontendCertificate, p.Routes)
	return e
}
