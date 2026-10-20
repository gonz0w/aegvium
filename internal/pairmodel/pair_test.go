// SPDX-License-Identifier: BSD-3-Clause
package pairmodel

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"
)

type vector struct {
	ID      string `json:"id"`
	Hex     string `json:"descriptor_hex"`
	SHA     string `json:"sha256"`
	Offsets struct {
		Routes   []map[string]int `json:"routes"`
		Fixed    int              `json:"fixed_limits"`
		Requests int              `json:"requests"`
		Sockets  int              `json:"data_sockets"`
	} `json:"offsets"`
}
type corpus struct {
	Valid, Invalid []vector
	Equality       []struct {
		Left, Right string
		Equal       bool
	} `json:"equality_oracles"`
}

func goldens(t testing.TB) corpus {
	t.Helper()
	b, e := os.ReadFile("testdata/independent.json")
	if e != nil {
		t.Fatal(e)
	}
	var c corpus
	if e = json.Unmarshal(b, &c); e != nil {
		t.Fatal(e)
	}
	return c
}
func raw(t testing.TB, v vector) []byte {
	t.Helper()
	b, e := hex.DecodeString(v.Hex)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func TestIndependentDescriptors(t *testing.T) {
	c := goldens(t)
	byID := map[string]*Descriptor{}
	for _, v := range c.Valid {
		t.Run(v.ID, func(t *testing.T) {
			input := raw(t, v)
			d, e := Parse(input)
			if e != nil {
				t.Fatal(e)
			}
			byID[v.ID] = d
			if !bytes.Equal(d.Bytes(), input) || d.Digest() != "sha256:"+v.SHA {
				t.Fatal("independent complete-byte/hash mismatch")
			}
			input[0] = '!'
			out := d.Bytes()
			out[0] = '!'
			if !bytes.Equal(d.Bytes(), raw(t, v)) {
				t.Fatal("caller storage aliases descriptor")
			}
		})
	}
	for _, v := range c.Invalid {
		t.Run(v.ID, func(t *testing.T) {
			if d, e := Parse(raw(t, v)); e == nil || d != nil {
				t.Fatal("independent rejected input accepted")
			}
		})
	}
	for _, v := range c.Equality {
		if byID[v.Left].Equal(byID[v.Right]) != v.Equal {
			t.Fatal("independent equality mismatch")
		}
	}
	if (&Descriptor{}).Equal(&Descriptor{}) || (*Descriptor)(nil).Equal(nil) || (&Descriptor{}).Digest() != "" {
		t.Fatal("zero value available")
	}
}
func TestTruncationAndFixedFields(t *testing.T) {
	v := goldens(t).Valid[0]
	b := raw(t, v)
	for n := 0; n < len(b); n++ {
		if d, e := Parse(b[:n]); e == nil || d != nil {
			t.Fatalf("proper prefix %d accepted", n)
		}
	}
	for i := v.Offsets.Fixed; i < len(b); i++ {
		bad := bytes.Clone(b)
		bad[i] ^= 1
		if _, e := Parse(bad); e == nil {
			t.Fatalf("changed fixed byte %d accepted", i)
		}
	}
	for _, key := range []string{"id_length", "public_dns_length", "peer_count", "peer_0_length", "inspector_address_length", "inspector_dns_length"} {
		bad := bytes.Clone(b)
		at := v.Offsets.Routes[0][key]
		bad[at] = 0
		if key == "public_dns_length" || key == "peer_0_length" || key == "inspector_dns_length" {
			bad[at+1] = 0
		}
		if _, e := Parse(bad); e == nil {
			t.Fatal("zero length/count accepted", key)
		}
	}
	bad := append(bytes.Clone(b), 0)
	if _, e := Parse(bad); e == nil {
		t.Fatal("trailing data accepted")
	}
}
func TestTextAndAddressBoundaries(t *testing.T) {
	for _, s := range []string{"a", "abc_19"} {
		if !identifier(s) {
			t.Fatal("valid ID", s)
		}
	}
	for _, s := range []string{"", "_abc", "a-b", "A"} {
		if identifier(s) {
			t.Fatal("invalid ID", s)
		}
	}
	for _, s := range []string{"a", "front.internal", "a-b.test"} {
		if !dns(s) {
			t.Fatal("valid DNS", s)
		}
	}
	for _, s := range []string{"a.", "A.test", "*.test", "1.2.3.4", "-a.test", "a..test"} {
		if dns(s) {
			t.Fatal("invalid DNS", s)
		}
	}
}
func FuzzModel(f *testing.F) {
	for _, v := range goldens(f).Valid {
		f.Add(raw(f, v))
	}
	for _, v := range goldens(f).Invalid {
		f.Add(raw(f, v))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		d, e := Parse(b)
		if e != nil {
			if d != nil {
				t.Fatal("usable descriptor on error")
			}
			return
		}
		out := d.Bytes()
		other, e := Parse(out)
		if e != nil || !bytes.Equal(out, b) || !d.Equal(other) || d.Digest() != other.Digest() {
			t.Fatal("complete byte round trip failed")
		}
	})
}

// Alter complete independent descriptor bytes without using a product encoder.
// Unchanged suffixes retain every downstream field and fixed trailer.
func replaceField(b []byte, at, width int, value string) []byte {
	old := int(b[at])
	if width == 2 {
		old = int(b[at])<<8 | int(b[at+1])
	}
	out := bytes.Clone(b[:at])
	if width == 1 {
		out = append(out, byte(len(value)))
	} else {
		out = append(out, byte(len(value)>>8), byte(len(value)))
	}
	out = append(out, value...)
	return append(out, b[at+width+old:]...)
}
func TestCompleteFieldAndCountBounds(t *testing.T) {
	c := goldens(t)
	var minimal vector
	for _, v := range c.Valid {
		if v.ID == "minimum-reachable-complete-descriptor" {
			minimal = v
		}
	}
	b := raw(t, minimal)
	r := minimal.Offsets.Routes[0]
	check := func(name string, in []byte, want bool) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			_, e := Parse(in)
			if (e == nil) != want {
				t.Fatalf("expected accept=%v, got %v", want, e)
			}
		})
	}
	for _, n := range []int{32, 33} {
		check("ID"+string(rune('a'+n)), replaceField(b, r["id_length"], 1, strings.Repeat("a", n)), n == 32)
	}
	for _, n := range []int{253, 254} {
		name := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", n-192)
		for _, key := range []string{"public_dns_length", "peer_0_length", "inspector_dns_length"} {
			check(key+strconv.Itoa(n), replaceField(b, r[key], 2, name), n == 253)
		}
	}
	for _, address := range []string{"0.0.0.0", "::", "224.0.0.1", "ff02::1", "255.255.255.255", "fe80::1%em0", "2001:0db8::1", strings.Repeat("1", 46)} {
		check("address-"+address, replaceField(b, r["inspector_address_length"], 1, address), false)
	}
	for _, address := range []string{"127.0.0.1", "169.254.1.2", "::1", "fe80::1", "eeee:ffff:ffff:ffff:ffff:ffff:ffff:ffff"} {
		check("address-"+address, replaceField(b, r["inspector_address_length"], 1, address), true)
	}
	for _, at := range []int{0, 8, 40, r["policy_pin"]} {
		in := bytes.Clone(b)
		in[at] = 'G'
		check("lexical"+strconv.Itoa(at), in, false)
	}
	route := b[r["start"]:r["end"]]
	for _, n := range []int{8, 9} {
		in := bytes.Clone(b[:48])
		in[47] = byte(n)
		for i := 0; i < n; i++ {
			one := bytes.Clone(route)
			one[r["id"]-r["start"]] = byte('a' + i)
			one[r["public_dns"]-r["start"]] = byte('a' + i)
			in = append(in, one...)
		}
		in = append(in, b[minimal.Offsets.Fixed:]...)
		check("route-count"+strconv.Itoa(n), in, n == 8)
	}
	for _, n := range []int{8, 9} {
		at := r["peer_count"]
		end := r["inspector_address_length"]
		in := bytes.Clone(b[:at])
		in = append(in, byte(n))
		for i := 0; i < n; i++ {
			in = append(in, 0, 1, byte('a'+i))
		}
		in = append(in, b[end:]...)
		check("peer-count"+strconv.Itoa(n), in, n == 8)
	}
}

func TestDuplicateIdentitiesAndSingleLabelBound(t *testing.T) {
	c := goldens(t)
	var two vector
	for _, v := range c.Valid {
		if v.ID == "two-routes-sorted-v4-v6" {
			two = v
		}
	}
	b := raw(t, two)
	r0, r1 := two.Offsets.Routes[0], two.Offsets.Routes[1]
	firstID := string(b[r0["id"] : r0["id"]+int(b[r0["id_length"]])])
	if _, e := Parse(replaceField(b, r1["id_length"], 1, firstID)); e == nil {
		t.Fatal("duplicate route ID with distinct authorities accepted")
	}
	v := c.Valid[0]
	b = raw(t, v)
	r := v.Offsets.Routes[0]
	n := int(b[r["peer_0_length"]])<<8 | int(b[r["peer_0_length"]+1])
	firstPeer := string(b[r["peer_0"] : r["peer_0"]+n])
	if _, e := Parse(replaceField(b, r["peer_1_length"], 2, firstPeer)); e == nil {
		t.Fatal("duplicate complete peer accepted")
	}
	for _, n := range []int{63, 64} {
		_, e := Parse(replaceField(b, r["public_dns_length"], 2, strings.Repeat("a", n)))
		if (e == nil) != (n == 63) {
			t.Fatal("isolated DNS label bound", n, e)
		}
	}
}
