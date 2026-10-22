// SPDX-License-Identifier: BSD-3-Clause
package backendconfig

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func literal(t *testing.T) ([]byte, []byte) {
	t.Helper()
	read := func(path, key string) []byte {
		b, e := os.ReadFile(path)
		if e != nil {
			t.Fatal(e)
		}
		var f map[string]any
		if json.Unmarshal(b, &f) != nil {
			t.Fatal("public fixture invalid")
		}
		text, ok := f[key].(string)
		if !ok {
			t.Fatal("public fixture field missing")
		}
		out, e := hex.DecodeString(text)
		if e != nil {
			t.Fatal(e)
		}
		return out
	}
	return read("testdata/binding.json", "backend_hex"), read("../requestctx/testdata/pair_prepared.json", "descriptor_hex")
}

func replaceText(t *testing.T, input []byte, old, value string, width int) []byte {
	t.Helper()
	at := bytes.Index(input, []byte(old))
	if at < width {
		t.Fatal("independent fixture field absent")
	}
	out := bytes.Clone(input[:at-width])
	if width == 1 {
		out = append(out, byte(len(value)))
	} else {
		out = binary.BigEndian.AppendUint16(out, uint16(len(value)))
	}
	out = append(out, value...)
	return append(out, input[at+len(old):]...)
}

func TestBackendConfigIndependentBoundBinding(t *testing.T) {
	b, d := literal(t)
	h := sha256.Sum256(b)
	if len(b) != 213 || hex.EncodeToString(h[:]) != "5e4c6aec468aa1309aa2e7bf470637ce7b9860f333d484fc1d4af481b5e1aa5e" {
		t.Fatal("independent pre-code literal changed")
	}
	c, e := Parse(b, d)
	if e != nil || c.Generation != "0123456789abcdef0123456789abcdef" || c.ClientRole != "aeg-data.internal.test" || len(c.Routes) != 1 || c.Routes[0].ID != "app_primary" || c.Routes[0].Address.String() != "192.0.2.81:9443" || c.Routes[0].ServerName != "app-backend.internal.test" {
		t.Fatal("private backend configuration not bound exactly")
	}
	if c.PairDigest != sha256.Sum256(d) || c.ClientAnchor[0] != 32 || c.ClientAnchor[31] != 63 || c.Routes[0].ServerAnchor[0] != 64 || c.Routes[0].ServerAnchor[31] != 95 {
		t.Fatal("explicit anchors changed")
	}
	b[8] ^= 1
	d[8] ^= 1
	if c.Generation != "0123456789abcdef0123456789abcdef" {
		t.Fatal("configuration aliases input")
	}
}

func TestBackendConfigVersion2BindsFullDescriptor(t *testing.T) {
	b, _ := literal(t)
	raw, err := os.ReadFile("../requestctx/testdata/pair2_prepared.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Row struct {
			Descriptor string `json:"descriptor_hex"`
			Prepared   string `json:"prepared_hex"`
		} `json:"same_address_distinct_ports"`
	}
	if json.Unmarshal(raw, &f) != nil {
		t.Fatal("public literal")
	}
	d, err := hex.DecodeString(f.Row.Descriptor)
	if err != nil {
		t.Fatal(err)
	}
	q, err := hex.DecodeString(f.Row.Prepared)
	if err != nil || len(q) != 104 {
		t.Fatal("public tuple")
	}
	if _, err := Parse(b, d); err == nil {
		t.Fatal("old private binding accepted")
	}
	copy(b[40:72], q[40:72]) // Independent full-D literal, not production hashing.
	c, err := Parse(b, d)
	if err != nil || len(c.Routes) != 1 || c.Routes[0].Address.String() != "192.0.2.81:9443" {
		t.Fatal("new exact private binding refused", err)
	}
	// Alter DATA alone; immutable backend material must be explicitly rebound.
	at := bytes.LastIndex(d, []byte("192.0.2.10")) + len("192.0.2.10") + 1
	d[at] ^= 1
	if _, err := Parse(b, d); err == nil {
		t.Fatal("DATA-only descriptor change kept private binding")
	}
}

func TestBackendConfigRefusesUnboundAndUnsupportedInput(t *testing.T) {
	b, d := literal(t)
	for _, n := range []int{0, 7, 8, 39, 40, 71, 72, 94, 126, 127, 212} {
		if _, e := Parse(b[:n], d); e == nil {
			t.Fatal("truncated configuration accepted")
		}
	}
	for _, input := range [][]byte{append(bytes.Clone(b), 0), make([]byte, 8193)} {
		if _, e := Parse(input, d); e == nil {
			t.Fatal("tail or cap+1 accepted")
		}
	}
	for _, at := range []int{0, 8, 40} {
		bad := bytes.Clone(b)
		bad[at] ^= 1
		if _, e := Parse(bad, d); e == nil {
			t.Fatal("magic/generation/digest mismatch accepted")
		}
	}
	for _, value := range []string{"0.0.0.0", "224.0.0.1", "255.255.255.255", "192.000.2.81", "::1", "backend.internal.test"} {
		if _, e := Parse(replaceText(t, b, "192.0.2.81", value, 1), d); e == nil {
			t.Fatal("unsupported address accepted")
		}
	}
	for _, value := range []string{"front-a.internal.test", "inspect.internal.test", "app.example.test", "*.internal.test", "Aeg-data.internal.test"} {
		if _, e := Parse(replaceText(t, b, "aeg-data.internal.test", value, 2), d); e == nil {
			t.Fatal("invalid or conflicting client role accepted")
		}
	}
	for _, value := range []string{"front-a.internal.test", "inspect.internal.test", "aeg-data.internal.test", "*.internal.test"} {
		if _, e := Parse(replaceText(t, b, "app-backend.internal.test", value, 2), d); e == nil {
			t.Fatal("invalid or conflicting server role accepted")
		}
	}
	if _, e := Parse(replaceText(t, b, "app_primary", "other_route", 1), d); e == nil {
		t.Fatal("foreign route accepted")
	}
	portAt := bytes.Index(b, []byte("192.0.2.81")) + len("192.0.2.81")
	badPort := bytes.Clone(b)
	badPort[portAt], badPort[portAt+1] = 0, 0
	if _, e := Parse(badPort, d); e == nil {
		t.Fatal("zero backend port accepted")
	}
	bad := bytes.Clone(d)
	bad[len(bad)-86] ^= 1
	if _, e := Parse(b, bad); e == nil {
		t.Fatal("other complete descriptor accepted")
	}
	at := bytes.Index(b, []byte("app_primary"))
	bad = bytes.Clone(b)
	bad[at-2] = 0
	if _, e := Parse(bad, d); e == nil {
		t.Fatal("incomplete route coverage accepted")
	}
}
