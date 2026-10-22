// SPDX-License-Identifier: BSD-3-Clause
package requestctx

// Inert public bytes only; no TLS/material constructor, socket or process.
import (
	"bytes"
	"context"
	hexbytes "encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/gonz0w/aegvium/internal/pairmodel"
)

func pair2Fixture(t *testing.T, key string) (*pairedSnapshot, []byte, []byte) {
	t.Helper()
	raw, err := os.ReadFile("testdata/pair2_prepared.json")
	if err != nil {
		t.Fatal(err)
	}
	var all map[string]json.RawMessage
	if json.Unmarshal(raw, &all) != nil {
		t.Fatal("invalid independent fixture")
	}
	if key == "joint" {
		b, err := os.ReadFile("testdata/pair2_joint.json")
		if err != nil {
			t.Fatal(err)
		}
		all[key] = b
	}
	var row struct {
		Descriptor string `json:"descriptor_hex"`
		Prepared   string `json:"prepared_hex"`
	}
	if json.Unmarshal(all[key], &row) != nil {
		t.Fatal("missing independent literal")
	}
	d, err := hexbytes.DecodeString(row.Descriptor)
	if err != nil {
		t.Fatal(err)
	}
	q, err := hexbytes.DecodeString(row.Prepared)
	if err != nil {
		t.Fatal(err)
	}
	s, err := newPairedSnapshot(d)
	if err != nil || len(q) != 104 || !bytes.Equal(s.tuple[:], q) {
		t.Fatal("independent P3 tuple mismatch", err)
	}
	return s, d, q
}

func TestPairSourceVersion2ExactControlAndData(t *testing.T) {
	for _, key := range []string{"same_address_distinct_ports", "distinct_ipv6_same_port", "supervisor_generation1"} {
		s, raw, q := pair2Fixture(t, key)
		d, err := pairmodel.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		p, err := d.Projection()
		if err != nil || p.Profile != "M2-H1/3" || len(p.Routes) != 1 {
			t.Fatal("profile projection")
		}
		r := p.Routes[0]
		if key != "distinct_ipv6_same_port" && (r.InspectorAddress != "192.0.2.10" || r.InspectorPort != 8443 || r.DataAddress != "192.0.2.10" || r.DataPort != 9443) {
			t.Fatal("operation tuple changed")
		}
		if key == "distinct_ipv6_same_port" && (r.InspectorAddress != "2001:db8::10" || r.DataAddress != "2001:db8::11" || r.InspectorPort != 8443 || r.DataPort != 8443) {
			t.Fatal("distinct numeric addresses rejected or rewritten")
		}
		if s.address != r.InspectorAddress || s.port != r.InspectorPort || s.dataAddress != r.DataAddress || s.dataPort != r.DataPort || s.context.profile != "M2-H1/3" {
			t.Fatal("local immutable binding")
		}
		// Old control path and HTTP grammar remain unchanged for Q3.
		if pairHTTPStatus(s, pairHeader(), q) != 200 || !bytes.HasSuffix(pairResponse(s, 200), q) {
			t.Fatal("P3 control comparison changed")
		}
		if s.context.Record(context.Background(), Peer{}, Request{}, &Recorder{}) != ErrPeer {
			t.Fatal("tuple minted Peer")
		}
		p.Routes[0].FrontendPeers[0] = "mutated.test"
		raw[0] ^= 1
		again, err := d.Projection()
		if err != nil || again.Routes[0].FrontendPeers[0] != "front-a.internal.test" {
			t.Fatal("projection/input alias")
		}
	}
	old, _, _ := pairFixture(t)
	if old.dataAddress != "" || old.dataPort != 0 || old.context.profile != "M2-H1/1" {
		t.Fatal("legacy inferred DATA or new profile")
	}
	joint, _, _ := pair2Fixture(t, "joint")
	if joint.address != "192.0.2.10" || joint.port != 8443 || joint.dataAddress != "192.0.2.20" || joint.dataPort != 9443 {
		t.Fatal("joint Vect/Aeg fixture endpoints differ")
	}
}

func TestPairSourceVersion2MutationAndBounds(t *testing.T) {
	s, raw, q := pair2Fixture(t, "same_address_distinct_ports")
	// Literal endpoint sequence from the independent oracle, not an encoder.
	control := bytes.Index(raw, []byte("\x0a192.0.2.10\x20\xfb"))
	data := control + 13
	if control < 0 || !bytes.Equal(raw[data:data+13], []byte("\x0a192.0.2.10\x24\xe3")) {
		t.Fatal("fixture offsets")
	}
	for _, at := range []int{control + 10, control + 12, data + 10, data + 12} {
		changed := bytes.Clone(raw)
		changed[at] ^= 1
		next, err := newPairedSnapshot(changed)
		if err != nil || bytes.Equal(q[40:72], next.tuple[40:72]) || !bytes.Equal(q[72:], next.tuple[72:]) {
			t.Fatal("endpoint not bound in full D/Q")
		}
		if at >= data && (s.address != next.address || s.port != next.port) {
			t.Fatal("DATA changed CONTROL selection")
		}
		if at < data && (s.dataAddress != next.dataAddress || s.dataPort != next.dataPort) {
			t.Fatal("CONTROL changed DATA selection")
		}
		if pairHTTPStatus(s, pairHeader(), next.tuple[:]) != 409 {
			t.Fatal("different D accepted")
		}
	}
	for _, mutate := range []func([]byte){
		func(b []byte) { b[6] = '1' }, func(b []byte) { b[6] = '3' },
		func(b []byte) { b[46] = '1' }, func(b []byte) { b[46] = '2' },
		func(b []byte) { copy(b[data:data+13], b[control:control+13]) },
		func(b []byte) { b[data+11] = 0; b[data+12] = 0 },
		func(b []byte) { b[control+11] = 0; b[control+12] = 0 },
		func(b []byte) { b[data+1] = '0' }, func(b []byte) { b[data+1] = 'x' },
		func(b []byte) { b[len(b)-1] = 9 }, func(b []byte) { b[len(b)-3] ^= 1 },
	} {
		bad := bytes.Clone(raw)
		mutate(bad)
		if _, err := pairmodel.Parse(bad); err == nil {
			t.Fatal("invalid version/endpoint/limit accepted")
		}
	}
	for n := 0; n < len(raw); n++ {
		if _, err := pairmodel.Parse(raw[:n]); err == nil {
			t.Fatal("truncation accepted", n)
		}
	}
	for _, bad := range [][]byte{append(bytes.Clone(raw), 0), make([]byte, 8193)} {
		if _, err := pairmodel.Parse(bad); err == nil {
			t.Fatal("suffix/cap accepted")
		}
	}
	_, old, _ := pairFixture(t)
	old[46] = '3'
	if _, err := pairmodel.Parse(old); err == nil {
		t.Fatal("AGPAIR1/P3 accepted")
	}
}

func twoPair2Routes(t *testing.T, raw []byte) ([]byte, int) {
	t.Helper()
	// One independent fixture route is duplicated with a strictly later ID of
	// the same width and a distinct public authority. No production builder.
	end := len(raw) - 22
	route := bytes.Clone(raw[48:end])
	copy(route[1:12], "bpp_primary")
	i := bytes.Index(route, []byte("app.example.test"))
	copy(route[i:i+16], "bpp.example.test")
	out := append(bytes.Clone(raw[:end]), route...)
	out = append(out, raw[end:]...)
	out[47] = 2
	return out, end
}

func TestPairSourceVersion2CrossRouteBinding(t *testing.T) {
	_, raw, _ := pair2Fixture(t, "same_address_distinct_ports")
	whole, second := twoPair2Routes(t, raw)
	if _, err := newPairedSnapshot(whole); err != nil {
		t.Fatal("matching operation tuple refused", err)
	}
	for _, needle := range [][]byte{[]byte("\x0a192.0.2.10\x20\xfb"), []byte("\x0a192.0.2.10\x24\xe3"), []byte("inspect.internal.test")} {
		bad := bytes.Clone(whole)
		at := second + bytes.Index(bad[second:], needle)
		bad[at+len(needle)-1] ^= 1
		if _, err := pairmodel.Parse(bad); err != nil {
			t.Fatal("mutation must be valid detached syntax", err)
		}
		if _, err := newPairedSnapshot(bad); err == nil {
			t.Fatal("cross-route tuple/role accepted")
		}
	}
	for _, offset := range []int{len(whole) - 22 - 64, len(whole) - 22 - 32} {
		bad := bytes.Clone(whole)
		bad[offset] ^= 1
		if _, err := newPairedSnapshot(bad); err == nil {
			t.Fatal("cross-route anchor mismatch accepted")
		}
	}
	// Current profile comes only from validated descriptor, never this header.
	s, _, _ := pair2Fixture(t, "same_address_distinct_ports")
	if pairHTTPStatus(s, []byte(strings.Replace(string(pairHeader()), "m2-h1-1", "m2-h1-3", 1)), s.tuple[:]) != 400 {
		t.Fatal("control path was renegotiated")
	}
}
