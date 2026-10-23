//go:build aegvium_frontend_source

// Adapted from private Vectivium e28959892903225887d855677c307712a59ce071; see LICENSE.Vectivium.
// No public relicensing is made.
package frontendclient

// ConfigurationTupleSource validates detached local configuration using the
// explicit AGPAIR1/M2-H1/1 or AGPAIR2/M2-H1/3 parser. It performs no credential, TLS, history or process
// operation. Its returned bytes are DATA, never a prepared/authenticated match,
// a consumed generation, freshness, readiness or frontend ownership.
func ConfigurationTupleSource(descriptor []byte, frontendRole string) ([104]byte, error) {
	p, err := parsePair(descriptor, frontendRole)
	if err != nil {
		return [104]byte{}, ErrUnavailable
	}
	return p.tuple, nil
}
