// SPDX-License-Identifier: BSD-3-Clause
package pairmodel

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
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
