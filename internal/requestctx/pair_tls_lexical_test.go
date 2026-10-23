//go:build aegvium_transport_source

// SPDX-License-Identifier: BSD-3-Clause
package requestctx

// Lexical dummy PEM and time-field tests ONLY. No certificate/key parse,
// verification, receiver constructor, tls.Conn or credential operation.
import (
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
	"time"
)

func TestPairSourcePEMStrictConsumption(t *testing.T) {
	// Public one-byte containers, never real key/certificate DER. Standard PEM
	// encoding is lexical serialization only; no key/X509 parser is called.
	cert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1}}))
	key := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1}}))
	if !certificateMaterial([]byte(cert), []byte(key)) {
		t.Fatal("lexically valid dummy PEM refused")
	}
	for _, bad := range []string{"junk\n" + cert, strings.Replace(cert, "AQ==", "%%%", 1) + cert, cert + "junk", string(pem.EncodeToMemory(&pem.Block{Type: "WRONG", Bytes: []byte{1}})) + cert} {
		if certificateMaterial([]byte(bad), []byte(key)) {
			t.Fatal("certificate skipped prefix/block accepted")
		}
	}
	for _, bad := range []string{"junk\n" + key, key + key, strings.Replace(key, "AQ==", "%%%", 1) + key, key + "junk"} {
		if certificateMaterial([]byte(cert), []byte(bad)) {
			t.Fatal("key skipped prefix/block accepted")
		}
	}
}
func TestPairSourceCurrentChainTimeIntersection(t *testing.T) {
	now := time.Unix(1000, 0)
	chain := []*x509.Certificate{
		{NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)},
		{NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Minute)},
	}
	v, ok := chainValidity(chain, now)
	if !ok || !v.from.Equal(now.Add(-time.Minute)) || !v.until.Equal(now.Add(time.Minute)) || v.current(v.until) {
		t.Fatal("chain validity boundary")
	}
	if _, ok := chainValidity([]*x509.Certificate{nil}, now); ok {
		t.Fatal("nil chain accepted")
	}
}
