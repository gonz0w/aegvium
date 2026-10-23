//go:build aegvium_transport_source

// SPDX-License-Identifier: BSD-3-Clause
package requestctx

import (
	"bytes"
	"crypto/sha256"
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

func bootstrapPacket(t *testing.T, descriptor, tuple []byte) []byte {
	t.Helper()
	// Independent frozen prefix for the retained313-byte descriptor. No
	// production bootstrap encoder is used to manufacture the expectation.
	prefix, err := hexbytes.DecodeString("4147424f4f54310a0139")
	if err != nil || len(descriptor) != 313 || len(tuple) != 104 {
		t.Fatal("invalid public bootstrap fixture")
	}
	return append(append(prefix, tuple...), descriptor...)
}

func TestPairBootstrapExactSnapshotRetainsSameEndpoint(t *testing.T) {
	_, descriptor, expected := pairFixture(t)
	packet := bootstrapPacket(t, descriptor, expected)
	if sum := sha256.Sum256(packet); hexbytes.EncodeToString(sum[:]) != "753758fa42082025c4f1d37ca496e641145de397071c22f904bcaa2480c0b366" {
		t.Fatal("independently frozen whole-packet fixture mismatch")
	}
	r := &bootstrapRead{frame: packet, n: 427}
	b := &inheritedPairBootstrap{endpoint: r}
	if err := b.consume(); err != nil {
		t.Fatal(err)
	}
	clear(packet)
	if !b.claimed || b.uncertain || b.snapshot == nil || !bytes.Equal(b.snapshot.tuple[:], expected) || b.endpoint != r || r.calls != 1 {
		t.Fatal("bootstrap did not preserve owned configuration/endpoint")
	}
	if b.consume() == nil || r.calls != 1 {
		t.Fatal("bootstrap was read twice")
	}
	// Matching configuration still supplies no Peer or receiver/launch issuer.
	if b.snapshot.context.Record(t.Context(), Peer{}, Request{}, &Recorder{}) != ErrPeer {
		t.Fatal("bootstrap minted Peer")
	}
}

func TestPairBootstrapVersion2ExactDescriptorAndTuple(t *testing.T) {
	_, descriptor, tuple := pair2Fixture(t, "same_address_distinct_ports")
	// Independent326-byte prefix and packet hash, frozen before source edits.
	prefix, err := hexbytes.DecodeString("4147424f4f54310a0146")
	if err != nil {
		t.Fatal(err)
	}
	packet := append(append(prefix, tuple...), descriptor...)
	if sum := sha256.Sum256(packet); len(packet) != 440 || hexbytes.EncodeToString(sum[:]) != "8ac237d672b44ac5aacf76e028ca03041e135660cd3c410d048c0f336e4f75ff" {
		t.Fatal("independent P3 packet mismatch")
	}
	r := &bootstrapRead{frame: packet, n: 440}
	b := &inheritedPairBootstrap{endpoint: r}
	if b.consume() != nil || b.snapshot == nil || b.endpoint != r || r.calls != 1 || b.snapshot.dataPort != 9443 || b.snapshot.port != 8443 || !bytes.Equal(b.snapshot.tuple[:], tuple) {
		t.Fatal("P3 bootstrap lost binding")
	}
	if b.consume() == nil || r.calls != 1 {
		t.Fatal("P3 bootstrap read twice")
	}
	// Old C cannot be paired with new descriptor bytes even with matching G.
	_, _, oldTuple := pairFixture(t)
	copy(packet[82:114], oldTuple[72:])
	bad := &bootstrapRead{frame: packet, n: 440}
	if (&inheritedPairBootstrap{endpoint: bad}).consume() == nil || bad.calls != 1 {
		t.Fatal("old capability accepted with new descriptor")
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
	r := &bootstrapRead{frame: bootstrapPacket(t, descriptor, want), n: 427}
	b := &inheritedPairBootstrap{endpoint: r}
	if b.consume() != nil || b.snapshot == nil || !bytes.Equal(b.snapshot.tuple[:], want) {
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
		{"short", 426, nil, -1, false}, {"invalid-count", 8308, nil, -1, false},
		{"negative-count", -1, nil, -1, false}, {"empty", 0, nil, -1, false},
		{"full-error", 427, io.ErrUnexpectedEOF, -1, false}, {"full-eof", 427, io.EOF, -1, false},
		{"magic", 427, nil, 0, false}, {"length", 427, nil, 8, false},
		{"tuple-magic", 427, nil, 10, false}, {"generation", 427, nil, 18, false},
		{"common-digest", 427, nil, 50, false}, {"contract", 427, nil, 82, false},
		{"descriptor-magic", 427, nil, 114, false}, {"descriptor-grammar", 427, nil, 161, false},
		{"panic", 0, nil, -1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			frame := bootstrapPacket(t, descriptor, expected)
			if tc.at >= 0 {
				frame[tc.at] ^= 1
			}
			r := &bootstrapRead{frame: frame, n: tc.n, err: tc.err, panics: tc.panics}
			b := &inheritedPairBootstrap{endpoint: r}
			if b.consume() == nil || !b.claimed || !b.uncertain || b.snapshot != nil || b.endpoint != r || r.calls != 1 {
				t.Fatal("uncertain bootstrap escaped/refunded ownership")
			}
			if b.consume() == nil || r.calls != 1 {
				t.Fatal("failed bootstrap retried")
			}
		})
	}
}

func TestPairBootstrapFramingRefusalConsumesActualRead(t *testing.T) {
	_, descriptor, expected := pairFixture(t)
	packet := bootstrapPacket(t, descriptor, expected)
	for _, size := range [][2]byte{{0, 0}, {0, 46}, {0x20, 1}, {0x39, 1}, {0, 47}, {0x20, 0}} {
		bad := bytes.Clone(packet)
		copy(bad[8:10], size[:])
		r := &bootstrapRead{frame: bad, n: len(bad)}
		b := &inheritedPairBootstrap{endpoint: r}
		if b.consume() == nil || b.consume() == nil || r.calls != 1 || !b.uncertain || b.snapshot != nil || b.endpoint != r {
			t.Fatal("invalid descriptor size retried or escaped ownership")
		}
	}
	// Old104, observed cap+1, extra byte, and coalesced later control all refuse.
	for _, frame := range [][]byte{expected, make([]byte, 8307), append(bytes.Clone(packet), 0), append(bytes.Clone(packet), make([]byte, 64)...)} {
		r := &bootstrapRead{frame: frame, n: len(frame)}
		b := &inheritedPairBootstrap{endpoint: r}
		if b.consume() == nil || !b.uncertain || b.snapshot != nil || r.calls != 1 {
			t.Fatal("invalid stream framing accepted")
		}
	}
	zero := bytes.Clone(packet)
	copy(zero[18:50], "00000000000000000000000000000000")
	copy(zero[122:154], "00000000000000000000000000000000")
	// Independent valid digest for that exact zero-generation descriptor:
	// isolate the zero guard rather than accidentally rejecting a stale hash.
	zeroDigest, err := hexbytes.DecodeString("fb1cbb6303fef567b601df7016a07e456abc8749215da8783abf316981c44fb4")
	if err != nil {
		t.Fatal(err)
	}
	copy(zero[50:82], zeroDigest)
	if sum := sha256.Sum256(zero); hexbytes.EncodeToString(sum[:]) != "0a10205d9a2ec54407978c36011a748f5fd6aaeb0c27d422a91a37ba8bfb346e" {
		t.Fatal("independent zero-packet fixture mismatch")
	}
	r := &bootstrapRead{frame: zero, n: len(zero)}
	if (&inheritedPairBootstrap{endpoint: r}).consume() == nil {
		t.Fatal("zero launch generation accepted")
	}
	nilEndpoint := &inheritedPairBootstrap{}
	if nilEndpoint.consume() == nil || !nilEndpoint.uncertain || nilEndpoint.consume() == nil {
		t.Fatal("nil endpoint accepted")
	}
}
