// SPDX-License-Identifier: BSD-3-Clause
package commission

import (
	"archive/tar"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"testing"
	"time"
)

// Independently reviewed literals retained before this encoder existed, shared
// with the actual C storage reader's fixtures. Do not use the encoder as oracle.
var states = []struct{ generation, frame string }{
	{"00000000000000000000000000000001", "4145474f574e310a430000000000000030303030303030303030303030303030303030303030303030303030303030304cd860d8c625934cf230cae2ae976a244a656c163e4e18a3354d08d8233fec98000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"},
	{"0123456789abcdef0123456789abcdef", "4145474f574e310a4300000000000000303132333435363738396162636465663031323334353637383961626364656582ded7d17c782ff3d8c75f8999bc0fa908f54ab3725b859921937ddb35efb956000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"},
	{"ffffffffffffffffffffffffffffffff", "4145474f574e310a430000000000000066666666666666666666666666666666666666666666666666666666666666654dc9b55bc4774721f97520d8033b1ec9af159a3c072b0d86fe4400b04e051616000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"},
}

const imagePin = "d855ba636ffdfea364522538421fa585c1927fe5ef4d8065b89549c6bf744213"

func fixture(t *testing.T) ([]byte, []byte, [32]byte) {
	t.Helper()
	raw, err := os.ReadFile("../requestctx/testdata/pair_prepared.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Descriptor string `json:"descriptor_hex"`
	}
	if json.Unmarshal(raw, &f) != nil {
		t.Fatal("invalid public fixture")
	}
	descriptor, err := hex.DecodeString(f.Descriptor)
	if err != nil {
		t.Fatal(err)
	}
	image := make([]byte, 4113)
	for i := range image {
		image[i] = byte(i % 251)
	}
	pin, err := hex.DecodeString(imagePin)
	if err != nil {
		t.Fatal(err)
	}
	var expected [32]byte
	copy(expected[:], pin)
	return descriptor, image, expected
}

func TestPayloadExactRuntimeFilesAndIndependentState(t *testing.T) {
	for _, tc := range states {
		t.Run(tc.generation, func(t *testing.T) {
			descriptor, image, pin := fixture(t)
			copy(descriptor[8:40], tc.generation)
			var out, repeat bytes.Buffer
			if Write(&out, descriptor, bytes.NewReader(image), int64(len(image)), pin) != nil ||
				Write(&repeat, descriptor, bytes.NewReader(image), int64(len(image)), pin) != nil {
				t.Fatal("payload rejected")
			}
			if !bytes.Equal(out.Bytes(), repeat.Bytes()) {
				t.Fatal("payload metadata is nondeterministic")
			}
			state, err := hex.DecodeString(tc.frame)
			if err != nil || len(state) != 128 {
				t.Fatal("invalid independent literal")
			}
			want := []struct {
				path string
				mode int64
				data []byte
			}{
				{"usr/local/libexec/aegvium/inspector", 0555, image},
				{"var/db/aegvium/inspector.pin", 0600, []byte(imagePin + "\n")},
				{"var/db/aegvium/pair.snapshot", 0600, descriptor},
				{"var/db/aegvium/launch.intent", 0600, []byte(tc.generation + "\n")},
				{"var/db/aegvium/launch.state", 0600, state},
			}
			r := tar.NewReader(bytes.NewReader(out.Bytes()))
			for _, f := range want {
				h, err := r.Next()
				if err != nil || h.Name != f.path || h.Mode != f.mode || h.Size != int64(len(f.data)) ||
					h.Typeflag != tar.TypeReg || h.Linkname != "" || h.Uid != 0 || h.Gid != 0 ||
					h.Uname != "root" || h.Gname != "wheel" || h.Format != tar.FormatUSTAR ||
					!h.ModTime.Equal(time.Unix(0, 0)) || len(h.PAXRecords) != 0 {
					t.Fatal("unexpected payload member or metadata")
				}
				got, err := io.ReadAll(r)
				if err != nil || !bytes.Equal(got, f.data) {
					t.Fatal("payload bytes differ from independent runtime fixture")
				}
			}
			if _, err := r.Next(); err != io.EOF {
				t.Fatal("extra payload member")
			}
		})
	}
}

func TestPayloadInvalidInputBeforeOutput(t *testing.T) {
	descriptor, image, pin := fixture(t)
	badGrammar := bytes.Clone(descriptor)
	badGrammar[47] = 0
	zero := bytes.Clone(descriptor)
	copy(zero[8:40], "00000000000000000000000000000000")
	for _, input := range [][]byte{nil, descriptor[:46], append(bytes.Clone(descriptor), 0),
		make([]byte, 8193), badGrammar, zero} {
		var out bytes.Buffer
		if Write(&out, input, bytes.NewReader(image), int64(len(image)), pin) == nil || out.Len() != 0 {
			t.Fatal("invalid descriptor produced output")
		}
	}
	for _, n := range []int64{-1, 0, MaxImageBytes + 1} {
		var out bytes.Buffer
		if Write(&out, descriptor, bytes.NewReader(image), n, pin) == nil || out.Len() != 0 {
			t.Fatal("out-of-bound size produced output")
		}
	}
	if Write(nil, descriptor, bytes.NewReader(image), 4113, pin) == nil ||
		Write(io.Discard, descriptor, nil, 4113, pin) == nil {
		t.Fatal("nil endpoint accepted")
	}
}

type imageFailure struct {
	*bytes.Reader
	tailErr error
}

func (r imageFailure) Read(p []byte) (int, error) {
	if r.Len() == 0 {
		return 0, r.tailErr
	}
	return r.Reader.Read(p)
}

func TestPayloadImageFailureNeverEmitsCheckpoint(t *testing.T) {
	descriptor, image, pin := fixture(t)
	for _, tc := range []struct {
		name  string
		input io.Reader
		pin   [32]byte
	}{
		{"short", bytes.NewReader(image[:4112]), pin},
		{"long", bytes.NewReader(append(bytes.Clone(image), 1)), pin},
		{"read-error", imageFailure{bytes.NewReader(image[:100]), io.ErrUnexpectedEOF}, pin},
		{"eof-error", imageFailure{bytes.NewReader(image), io.ErrUnexpectedEOF}, pin},
		{"eof-stall", imageFailure{bytes.NewReader(image), nil}, pin},
		{"digest", bytes.NewReader(image), [32]byte{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			if Write(&out, descriptor, tc.input, 4113, tc.pin) == nil ||
				bytes.Contains(out.Bytes(), []byte("var/db/aegvium/launch.state")) {
				t.Fatal("incomplete image was finalized or emitted initial state")
			}
		})
	}
}

type failOutput struct {
	remaining int
	short     bool
}

func (w *failOutput) Write(p []byte) (int, error) {
	if len(p) <= w.remaining {
		w.remaining -= len(p)
		return len(p), nil
	}
	n := w.remaining
	w.remaining = 0
	if w.short {
		return n, nil
	}
	return n, io.ErrClosedPipe
}

func TestPayloadHeaderBodyAndFinalizationFailures(t *testing.T) {
	descriptor, image, pin := fixture(t)
	var complete bytes.Buffer
	if Write(&complete, descriptor, bytes.NewReader(image), 4113, pin) != nil {
		t.Fatal("control failed")
	}
	// Headers, image body/padding, each metadata body and both EOF blocks.
	for _, n := range []int{0, 511, 512, 1024, 4624, 5119, 5120, 5632, 6144,
		6656, 7168, 7680, 8192, complete.Len() - 1024, complete.Len() - 1} {
		for _, short := range []bool{false, true} {
			w := &failOutput{remaining: n, short: short}
			if Write(w, descriptor, bytes.NewReader(image), 4113, pin) == nil {
				t.Fatal("truncated output reported success", n, short)
			}
		}
	}
}

type mutateDescriptor struct {
	*bytes.Reader
	descriptor []byte
}

func (r mutateDescriptor) Read(p []byte) (int, error) {
	clear(r.descriptor)
	return r.Reader.Read(p)
}

func TestPayloadDetachesDescriptorBeforeImageIO(t *testing.T) {
	descriptor, image, pin := fixture(t)
	want := bytes.Clone(descriptor)
	var out bytes.Buffer
	if Write(&out, descriptor, mutateDescriptor{bytes.NewReader(image), descriptor}, 4113, pin) != nil {
		t.Fatal("detached source failed")
	}
	r := tar.NewReader(bytes.NewReader(out.Bytes()))
	for {
		h, err := r.Next()
		if err == io.EOF {
			t.Fatal("snapshot missing")
		}
		if err != nil {
			t.Fatal(err)
		}
		if h.Name == "var/db/aegvium/pair.snapshot" {
			got, err := io.ReadAll(r)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatal("borrowed descriptor escaped")
			}
			return
		}
	}
}
