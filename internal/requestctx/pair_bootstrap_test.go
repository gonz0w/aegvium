//go:build aegvium_transport_source

// SPDX-License-Identifier: BSD-3-Clause
package requestctx

import (
	"bytes"
	hexbytes "encoding/hex"
	"io"
	"testing"
)

type bootstrapRead struct {
	frame  []byte
	n      int
	err    error
	panics bool
	calls  int
}

func (r *bootstrapRead) Read(p []byte) (int, error) {
	r.calls++
	if r.panics {
		panic("synthetic bootstrap read")
	}
	copy(p, r.frame)
	return r.n, r.err
}

func TestPairBootstrapExactSnapshotRetainsSameEndpoint(t *testing.T) {
	_, descriptor, expected := pairFixture(t)
	r := &bootstrapRead{frame: expected, n: 104}
	b := &inheritedPairBootstrap{endpoint: r}
	if err := b.consume(descriptor); err != nil {
		t.Fatal(err)
	}
	descriptor[0] = 'X'
	if !b.claimed || b.uncertain || b.snapshot == nil || !bytes.Equal(b.snapshot.tuple[:], expected) || b.endpoint != r || r.calls != 1 {
		t.Fatal("bootstrap did not preserve owned configuration/endpoint")
	}
	if b.consume(nil) == nil || r.calls != 1 {
		t.Fatal("bootstrap was read twice")
	}
	// Matching configuration still supplies no Peer or receiver/launch issuer.
	if b.snapshot.context.Record(t.Context(), Peer{}, Request{}, &Recorder{}) != ErrPeer {
		t.Fatal("bootstrap minted Peer")
	}
}

func TestPairBootstrapSupervisorGenerationLiteral(t *testing.T) {
	_, descriptor, _ := pairFixture(t)
	copy(descriptor[8:40], "00000000000000000000000000000001")
	// Independently frozen alongside the C producer's gen1 fixture, not hashed
	// or encoded by production code to manufacture this expected result.
	tail, err := hexbytes.DecodeString("2999ef5f7af41c6a2610f4ce5053b2b415ae291060bb0c60cde02a2b3cb035c0" +
		"1d987134086420d48b300a4cfda016ffc550a0bda6a6f20c58282db1b7d42dca")
	if err != nil {
		t.Fatal(err)
	}
	want := append([]byte("AGCHECK1"+"00000000000000000000000000000001"), tail...)
	r := &bootstrapRead{frame: want, n: 104}
	b := &inheritedPairBootstrap{endpoint: r}
	if b.consume(descriptor) != nil || b.snapshot == nil || !bytes.Equal(b.snapshot.tuple[:], want) {
		t.Fatal("supervisor/inspector frozen tuple mismatch")
	}
}

func TestPairBootstrapRefusalKeepsOwnedEndpoint(t *testing.T) {
	_, descriptor, expected := pairFixture(t)
	for _, tc := range []struct {
		name   string
		n      int
		err    error
		at     int
		panics bool
	}{
		{"short", 103, nil, -1, false}, {"invalid-count", 105, nil, -1, false},
		{"negative-count", -1, nil, -1, false}, {"empty", 0, nil, -1, false},
		{"full-error", 104, io.ErrUnexpectedEOF, -1, false}, {"full-eof", 104, io.EOF, -1, false},
		{"magic", 104, nil, 0, false}, {"generation", 104, nil, 8, false},
		{"common-digest", 104, nil, 40, false}, {"contract", 104, nil, 72, false},
		{"panic", 0, nil, -1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			frame := bytes.Clone(expected)
			if tc.at >= 0 {
				frame[tc.at] ^= 1
			}
			r := &bootstrapRead{frame: frame, n: tc.n, err: tc.err, panics: tc.panics}
			b := &inheritedPairBootstrap{endpoint: r}
			if b.consume(descriptor) == nil || !b.claimed || !b.uncertain || b.snapshot != nil || b.endpoint != r || r.calls != 1 {
				t.Fatal("uncertain bootstrap escaped/refunded ownership")
			}
			if b.consume(descriptor) == nil || r.calls != 1 {
				t.Fatal("failed bootstrap retried")
			}
		})
	}
}

func TestPairBootstrapInvalidInputConsumesAttemptWithoutIO(t *testing.T) {
	_, descriptor, expected := pairFixture(t)
	r := &bootstrapRead{frame: expected, n: 104}
	b := &inheritedPairBootstrap{endpoint: r}
	if b.consume(nil) == nil || b.consume(descriptor) == nil || r.calls != 0 || !b.uncertain || b.endpoint != r {
		t.Fatal("invalid descriptor did I/O or reopened attempt")
	}
	// S intentionally validates only the prefix before burning U. The full Go
	// parser must still refuse an invalid route-count suffix before reading.
	badGrammar := bytes.Clone(descriptor)
	badGrammar[47] = 0
	badOwner := &inheritedPairBootstrap{endpoint: r}
	if badOwner.consume(badGrammar) == nil || r.calls != 0 || !badOwner.uncertain {
		t.Fatal("invalid AGPAIR suffix reached bootstrap I/O")
	}
	nilEndpoint := &inheritedPairBootstrap{}
	if nilEndpoint.consume(descriptor) == nil || !nilEndpoint.uncertain {
		t.Fatal("nil endpoint accepted")
	}
}
