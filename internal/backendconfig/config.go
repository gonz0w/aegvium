// SPDX-License-Identifier: BSD-3-Clause
// Package backendconfig decodes bounded operator configuration, not admission,
// network containment, authentication, freshness or forwarding authority.
package backendconfig

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net/netip"
	"strings"

	"github.com/gonz0w/aegvium/internal/pairmodel"
)

var ErrConfig = errors.New("backend configuration unavailable")

type Route struct {
	ID, ServerName string
	Address        netip.AddrPort
	ServerAnchor   [32]byte
}
type Config struct {
	Generation, ClientRole   string
	PairDigest, ClientAnchor [32]byte
	Routes                   []Route
}

type reader struct {
	b   []byte
	at  int
	bad bool
}

func (r *reader) take(n int) []byte {
	if r.bad || n < 0 || n > len(r.b)-r.at {
		r.bad = true
		return nil
	}
	p := r.b[r.at : r.at+n]
	r.at += n
	return p
}
func (r *reader) u8() int {
	p := r.take(1)
	if len(p) != 1 {
		return 0
	}
	return int(p[0])
}
func (r *reader) u16() int {
	p := r.take(2)
	if len(p) != 2 {
		return 0
	}
	return int(binary.BigEndian.Uint16(p))
}
func (r *reader) text(n, limit int) string {
	if n < 1 || n > limit {
		r.bad = true
		return ""
	}
	return string(r.take(n))
}

func dns(s string) bool {
	if len(s) < 1 || len(s) > 253 || strings.ToLower(s) != s || strings.HasSuffix(s, ".") {
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

// Parse binds exact private route coverage to the actual inherited descriptor.
// This representation is private to Aegvium; it changes neither AGPAIR1 nor H1/1.
func Parse(input, descriptor []byte) (Config, error) {
	var zero Config
	if len(input) < 1 || len(input) > 8192 {
		return zero, ErrConfig
	}
	d, e := pairmodel.Parse(descriptor)
	if e != nil {
		return zero, ErrConfig
	}
	p, e := d.Projection()
	if e != nil {
		return zero, ErrConfig
	}
	r := reader{b: input}
	if string(r.take(8)) != "AGBACK1\n" {
		return zero, ErrConfig
	}
	c := Config{Generation: string(r.take(32))}
	copy(c.PairDigest[:], r.take(32))
	want := sha256.Sum256(d.Bytes())
	if r.bad || c.Generation != p.Generation || c.PairDigest != want {
		return zero, ErrConfig
	}
	c.ClientRole = r.text(r.u16(), 253)
	copy(c.ClientAnchor[:], r.take(32))
	roles := make(map[string]bool)
	public := make(map[string]bool)
	for _, route := range p.Routes {
		roles[route.InspectorName] = true
		public[route.PublicName] = true
		for _, name := range route.FrontendPeers {
			roles[name] = true
		}
	}
	if !dns(c.ClientRole) || roles[c.ClientRole] || public[c.ClientRole] {
		return zero, ErrConfig
	}
	count := r.u8()
	if count != len(p.Routes) || count < 1 || count > 8 {
		return zero, ErrConfig
	}
	for i := 0; i < count; i++ {
		entry := Route{ID: r.text(r.u8(), 32)}
		text := r.text(r.u8(), 15)
		address, e := netip.ParseAddr(text)
		port := r.u16()
		if e != nil || !address.Is4() || address.String() != text || address.IsUnspecified() || address.IsMulticast() || text == "255.255.255.255" || port < 1 {
			return zero, ErrConfig
		}
		entry.Address = netip.AddrPortFrom(address, uint16(port))
		entry.ServerName = r.text(r.u16(), 253)
		copy(entry.ServerAnchor[:], r.take(32))
		if r.bad || entry.ID != p.Routes[i].ID || !dns(entry.ServerName) || roles[entry.ServerName] || entry.ServerName == c.ClientRole {
			return zero, ErrConfig
		}
		c.Routes = append(c.Routes, entry)
	}
	if r.bad || r.at != len(input) {
		return zero, ErrConfig
	}
	return c, nil
}
