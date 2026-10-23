//go:build aegvium_frontend_source

// Adapted from private Vectivium e28959892903225887d855677c307712a59ce071; see LICENSE.Vectivium.
// No public relicensing is made.
package frontendclient

// Byte/configuration controls only. No NewSource/Match, credentials, TLS, dial,
// helper, writer, child, native service or actual accepted socket is invoked.
import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func descriptor2Fixture(t *testing.T) ([]byte, []byte) {
	t.Helper()
	raw, err := os.ReadFile("../requestctx/testdata/pair2_joint.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Descriptor string `json:"descriptor_hex"`
		Prepared   string `json:"prepared_hex"`
	}
	if json.Unmarshal(raw, &f) != nil {
		t.Fatal("literal fixture")
	}
	d, de := hex.DecodeString(f.Descriptor)
	q, qe := hex.DecodeString(f.Prepared)
	if de != nil || qe != nil || len(d) != 326 || len(q) != 104 {
		t.Fatal("literal fixture lengths")
	}
	return d, q
}

func TestDescriptor2ControlBindingAndLegacyAbsenceOfData(t *testing.T) {
	old, oldQ := fixture(t)
	one, err := parsePair(old, "front-a.internal.test")
	if err != nil || one.profile != "M2-H1/1" || one.dataAddress != "" || one.dataPort != 0 || !bytes.Equal(one.tuple[:], oldQ) {
		t.Fatal("legacy must remain control-only")
	}
	d, q := descriptor2Fixture(t)
	p, err := parsePair(d, "front-a.internal.test")
	if err != nil || p.profile != "M2-H1/3" || controlEndpoint(p) != "192.0.2.10:8443" || p.dataAddress != "192.0.2.20" || p.dataPort != 9443 || !bytes.Equal(p.tuple[:], q) {
		t.Fatal("explicit owned configuration binding")
	}
	const h = "POST /_aegvium/m2-h1-1/pair HTTP/1.1\r\nHost: inspect.internal.test:8443\r\nContent-Length: 104\r\nConnection: close\r\n\r\n"
	want := append([]byte(h), q...)
	if !bytes.Equal(controlRequest(p), want) {
		t.Fatal("control protocol changed or targets DATA")
	}
	local, err := ConfigurationTupleSource(d, "front-a.internal.test")
	if err != nil || local != p.tuple {
		t.Fatal("fixed local configuration record differs")
	}
	for i := range d {
		d[i] = 0
	}
	if !bytes.Equal(controlRequest(p), want) || local != p.tuple {
		t.Fatal("caller-owned descriptor retained")
	}
}

func TestDescriptor2BothEndpointsBindFullDigestWithoutFallback(t *testing.T) {
	d, _ := descriptor2Fixture(t)
	original, err := parsePair(d, "front-a.internal.test")
	if err != nil {
		t.Fatal(err)
	}
	dataAt := bytes.Index(d, []byte("192.0.2.20"))
	controlAt := bytes.Index(d, []byte("192.0.2.10"))
	if dataAt < 0 || controlAt < 0 {
		t.Fatal("literal endpoints")
	}
	for _, change := range []struct {
		name string
		at   int
		port uint16
		want string
	}{
		{"data", dataAt + len("192.0.2.20"), 9444, "192.0.2.10:8443"},
		{"control", controlAt + len("192.0.2.10"), 8444, "192.0.2.10:8444"},
	} {
		v := bytes.Clone(d)
		binary.BigEndian.PutUint16(v[change.at:change.at+2], change.port)
		p, err := parsePair(v, "front-a.internal.test")
		if err != nil || controlEndpoint(p) != change.want {
			t.Fatalf("%s endpoint selection", change.name)
		}
		if bytes.Equal(p.tuple[40:72], original.tuple[40:72]) || !bytes.Equal(p.tuple[:40], original.tuple[:40]) || !bytes.Equal(p.tuple[72:], original.tuple[72:]) {
			t.Fatalf("%s mutation must change fullD only", change.name)
		}
		if change.name == "data" && p.dataPort != 9444 || change.name == "control" && p.dataPort != original.dataPort {
			t.Fatal("endpoint fallback or unwanted DATA mutation")
		}
	}
	if bytes.Equal(original.tuple[72:], make([]byte, 32)) {
		t.Fatal("missing capability")
	}
}

func TestDescriptor2CrossRouteDataMismatchRefusesActualBinding(t *testing.T) {
	d, _ := descriptor2Fixture(t)
	first := bytes.Clone(d[48 : len(d)-22])
	second := bytes.Clone(first)
	second[11], second[14] = 'z', 'b'
	build := func(route []byte) []byte {
		out := bytes.Clone(d[:48])
		out[47] = 2
		out = append(out, first...)
		out = append(out, route...)
		return append(out, d[len(d)-22:]...)
	}
	if _, err := parsePair(build(second), "front-a.internal.test"); err != nil {
		t.Fatal("valid common pair")
	}
	for _, portOnly := range []bool{false, true} {
		changed := bytes.Clone(second)
		at := bytes.Index(changed, []byte("192.0.2.20"))
		if at < 0 {
			t.Fatal("literal DATA")
		}
		if portOnly {
			binary.BigEndian.PutUint16(changed[at+len("192.0.2.20"):], 9444)
		} else {
			changed[at+len("192.0.2.20")-1] = '1'
		}
		wire := build(changed)
		if _, err := parseDescriptor(wire); err != nil {
			t.Fatal("negative must remain structural configuration data")
		}
		if _, err := parsePair(wire, "front-a.internal.test"); err == nil {
			t.Fatal("mismatched DATA bound as a common actual control pair")
		}
	}
}
