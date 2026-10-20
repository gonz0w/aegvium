// SPDX-License-Identifier: BSD-3-Clause
// Package pairmodel models inert AGPAIR1 bytes. It does not authenticate peers,
// load trust anchors, establish freshness, serve traffic or grant permission.
package pairmodel

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

var ErrInput = errors.New("invalid pair descriptor")

// Descriptor is immutable, unbound data. Its zero value is unavailable.
type Descriptor struct{ data []byte }

func (d *Descriptor) Bytes() []byte {
	if d == nil {
		return nil
	}
	return slices.Clone(d.data)
}
func (d *Descriptor) Digest() string {
	if d == nil || len(d.data) == 0 {
		return ""
	}
	h := sha256.Sum256(d.data)
	return "sha256:" + hex.EncodeToString(h[:])
}

// Equal reports exact structural equality, never authenticated/readiness status.
func (d *Descriptor) Equal(other *Descriptor) bool {
	return d != nil && other != nil && len(d.data) > 0 && len(other.data) > 0 && bytes.Equal(d.data, other.data)
}

type cursor struct {
	data []byte
	at   int
	bad  bool
}

func (c *cursor) take(n int) []byte {
	if c.bad || n < 0 || n > len(c.data)-c.at {
		c.bad = true
		return nil
	}
	b := c.data[c.at : c.at+n]
	c.at += n
	return b
}
func (c *cursor) u8() int {
	b := c.take(1)
	if len(b) != 1 {
		return 0
	}
	return int(b[0])
}
func (c *cursor) u16() int {
	b := c.take(2)
	if len(b) != 2 {
		return 0
	}
	return int(binary.BigEndian.Uint16(b))
}
func (c *cursor) str8(max int) string {
	n := c.u8()
	if n < 1 || n > max {
		c.bad = true
		return ""
	}
	return string(c.take(n))
}
func (c *cursor) str16(max int) string {
	n := c.u16()
	if n < 1 || n > max {
		c.bad = true
		return ""
	}
	return string(c.take(n))
}
func Parse(in []byte) (*Descriptor, error) {
	if len(in) < 1 || len(in) > 8192 {
		return nil, ErrInput
	}
	c := cursor{data: in}
	if string(c.take(8)) != "AGPAIR1\n" || !lowerHex(string(c.take(32)), 32) || string(c.take(7)) != "M2-H1/1" {
		return nil, ErrInput
	}
	count := c.u8()
	if count < 1 || count > 8 {
		return nil, ErrInput
	}
	previous := ""
	authorities := map[string]bool{}
	for i := 0; i < count; i++ {
		id := c.str8(32)
		if !identifier(id) || id <= previous {
			return nil, ErrInput
		}
		previous = id
		public := c.str16(253)
		port := c.u16()
		if !dns(public) || port < 1 {
			return nil, ErrInput
		}
		authority := public + ":" + strconv.Itoa(port)
		if authorities[authority] {
			return nil, ErrInput
		}
		authorities[authority] = true
		if !lowerHex(string(c.take(64)), 64) {
			return nil, ErrInput
		}
		peers := c.u8()
		if peers < 1 || peers > 8 {
			return nil, ErrInput
		}
		last := ""
		for j := 0; j < peers; j++ {
			peer := c.str16(253)
			if !dns(peer) || peer <= last {
				return nil, ErrInput
			}
			last = peer
		}
		ip := c.str8(45)
		a, e := netip.ParseAddr(ip)
		if e != nil || a.String() != ip || a.Zone() != "" || a.Is4In6() || a.IsUnspecified() || a.IsMulticast() || ip == "255.255.255.255" {
			return nil, ErrInput
		}
		if c.u16() < 1 || !dns(c.str16(253)) {
			return nil, ErrInput
		}
		c.take(32)
		c.take(32)
	}
	for _, want := range []uint32{4096, 5120, 2048, 4096, 4096} {
		b := c.take(4)
		if len(b) != 4 || binary.BigEndian.Uint32(b) != want {
			return nil, ErrInput
		}
	}
	if c.u8() != 4 || c.u8() != 8 || c.bad || c.at != len(in) {
		return nil, ErrInput
	}
	return &Descriptor{slices.Clone(in)}, nil
}
func lowerHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, c := range []byte(s) {
		if !(c >= 'a' && c <= 'f' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}
func identifier(s string) bool {
	if len(s) < 1 || len(s) > 32 {
		return false
	}
	for i, c := range []byte(s) {
		if c >= 'a' && c <= 'z' || i > 0 && (c >= '0' && c <= '9' || c == '_') {
			continue
		}
		return false
	}
	return true
}
func dns(s string) bool {
	if len(s) < 1 || len(s) > 253 || strings.HasSuffix(s, ".") {
		return false
	}
	if _, e := netip.ParseAddr(s); e == nil {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range []byte(label) {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}
