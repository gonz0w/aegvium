//go:build aegvium_frontend_source

// Adapted from private Vectivium e28959892903225887d855677c307712a59ce071; see LICENSE.Vectivium.
// No public relicensing is made.
package frontendowner

import (
	"bytes"
	"encoding/pem"
	"testing"
)

// Public one-byte synthetic envelopes, not cryptographic keys/certificates.
// Tests never call a credential/TLS/native constructor.
func TestFrontendMaterialLexicalClosure(t *testing.T) {
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1}})
	key := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{2}})
	raw := append(bytes.Clone(cert), key...)
	c, k, err := splitFrontendPEM(raw)
	if err != nil || !bytes.Equal(bytes.TrimSpace(c), bytes.TrimSpace(cert)) || !bytes.Equal(bytes.TrimSpace(k), bytes.TrimSpace(key)) {
		t.Fatal("split exact envelopes")
	}
	for i := range raw {
		raw[i] = 0
	}
	if !bytes.Equal(bytes.TrimSpace(c), bytes.TrimSpace(cert)) || !bytes.Equal(bytes.TrimSpace(k), bytes.TrimSpace(key)) {
		t.Fatal("aliased input")
	}
	root, err := singleRootPEM(cert)
	if err != nil || !bytes.Equal(root, []byte{1}) {
		t.Fatal("root envelope")
	}
	bad := [][]byte{nil, cert, key, append(bytes.Clone(cert), cert...), append(bytes.Clone(key), key...), append(append(bytes.Clone(cert), key...), key...), append([]byte("garbage"), append(bytes.Clone(cert), key...)...), append(append(bytes.Clone(cert), key...), []byte("tail")...), bytes.Repeat([]byte{'a'}, 81921)}
	for _, r := range bad {
		if _, _, err := splitFrontendPEM(r); err == nil {
			t.Fatal("open material envelope")
		}
	}
	for _, r := range [][]byte{nil, key, append(bytes.Clone(cert), cert...), append([]byte("-----BEGIN CERTIFICATE-----\nbad!\n-----END CERTIFICATE-----\n"), cert...), append(bytes.Clone(cert), []byte("tail")...)} {
		if _, err := singleRootPEM(r); err == nil {
			t.Fatal("non-single root")
		}
	}
	if RunSource() != ErrUnavailable {
		t.Fatal("operational entry changed")
	}
}

func TestFrontendMaterialCountsAndUnknownBlocks(t *testing.T) {
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1}})
	key := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte{2}})
	if _, _, e := splitFrontendPEM(append(bytes.Repeat(cert, 8), key...)); e != nil {
		t.Fatal("eight certificates")
	}
	for _, raw := range [][]byte{append(bytes.Repeat(cert, 9), key...), append(pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte{2}}), cert...), append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Headers: map[string]string{"A": "B"}, Bytes: []byte{1}}), key...), append(append([]byte("-----BEGIN CERTIFICATE-----\nbad!\n-----END CERTIFICATE-----\n"), cert...), key...)} {
		if _, _, e := splitFrontendPEM(raw); e == nil {
			t.Fatal("unknown/ambiguous material")
		}
	}
}
