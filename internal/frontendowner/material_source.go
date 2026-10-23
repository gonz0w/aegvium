//go:build aegvium_frontend_source

// Adapted from private Vectivium e28959892903225887d855677c307712a59ce071; see LICENSE.Vectivium.
// No public relicensing is made.
package frontendowner

import (
	"bytes"
	"encoding/pem"
)

// Split only bounded lexical envelopes, without crypto, keys or file effects.
// Actual NewSource performs certificate/key parsing and pinned role checks.
func splitFrontendPEM(raw []byte) (cert, key []byte, err error) {
	if len(raw) == 0 || len(raw) > 81920 {
		return nil, nil, ErrUnavailable
	}
	count := 0
	for len(bytes.TrimSpace(raw)) != 0 {
		raw = bytes.TrimSpace(raw)
		if !bytes.HasPrefix(raw, []byte("-----BEGIN ")) {
			return nil, nil, ErrUnavailable
		}
		block, rest := pem.Decode(raw)
		if block == nil || len(block.Headers) != 0 {
			return nil, nil, ErrUnavailable
		}
		// pem.Decode may skip invalid leading blocks. Require the selected BEGIN.
		if !bytes.HasPrefix(raw, []byte("-----BEGIN "+block.Type+"-----")) {
			return nil, nil, ErrUnavailable
		}
		encoded := raw[:len(raw)-len(rest)]
		if len(block.Bytes) == 0 || bytes.Count(encoded, []byte("-----BEGIN ")) != 1 || bytes.Count(encoded, []byte("-----END ")) != 1 {
			return nil, nil, ErrUnavailable
		}
		switch block.Type {
		case "CERTIFICATE":
			count++
			if count > 8 || len(cert)+len(encoded) > 65536 {
				return nil, nil, ErrUnavailable
			}
			cert = append(cert, encoded...)
		case "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY":
			if len(key) != 0 || len(encoded) > 16384 {
				return nil, nil, ErrUnavailable
			}
			key = bytes.Clone(encoded)
		default:
			return nil, nil, ErrUnavailable
		}
		raw = rest
	}
	if count == 0 || len(key) == 0 {
		return nil, nil, ErrUnavailable
	}
	return cert, key, nil
}

func singleRootPEM(raw []byte) ([]byte, error) {
	if len(raw) == 0 || len(raw) > 32768 {
		return nil, ErrUnavailable
	}
	raw = bytes.TrimSpace(raw)
	block, rest := pem.Decode(raw)
	if !bytes.HasPrefix(raw, []byte("-----BEGIN CERTIFICATE-----")) || bytes.Count(raw, []byte("-----BEGIN ")) != 1 || block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 || len(block.Bytes) == 0 || len(block.Bytes) > 16384 {
		return nil, ErrUnavailable
	}
	return bytes.Clone(block.Bytes), nil
}
