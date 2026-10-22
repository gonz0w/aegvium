// SPDX-License-Identifier: BSD-3-Clause
package pairmodel

// Projection is detached configuration data, never peer or readiness authority.
type Projection struct {
	Generation, Profile string
	Routes              []Route
}
type Route struct {
	ID, PublicName, PolicyPin       string
	PublicPort                      uint16
	FrontendPeers                   []string
	InspectorAddress, InspectorName string
	InspectorPort                   uint16
	// InspectorAddress/Port are CONTROL. Empty DATA is AGPAIR1 CONTROL-only;
	// no caller may infer an application endpoint from the control tuple.
	DataAddress                  string
	DataPort                     uint16
	ServerAnchor, FrontendAnchor [32]byte
}

func (d *Descriptor) Projection() (Projection, error) {
	if d == nil || len(d.data) == 0 {
		return Projection{}, ErrInput
	}
	c := cursor{data: d.data}
	version := string(c.take(8))
	out := Projection{Generation: string(c.take(32)), Profile: string(c.take(7))}
	n := c.u8()
	for i := 0; i < n; i++ {
		r := Route{ID: c.str8(32), PublicName: c.str16(253), PublicPort: uint16(c.u16())}
		r.PolicyPin = string(c.take(64))
		peers := c.u8()
		for j := 0; j < peers; j++ {
			r.FrontendPeers = append(r.FrontendPeers, c.str16(253))
		}
		r.InspectorAddress = c.str8(45)
		r.InspectorPort = uint16(c.u16())
		if version == "AGPAIR2\n" {
			r.DataAddress = c.str8(45)
			r.DataPort = uint16(c.u16())
		}
		r.InspectorName = c.str16(253)
		copy(r.ServerAnchor[:], c.take(32))
		copy(r.FrontendAnchor[:], c.take(32))
		out.Routes = append(out.Routes, r)
	}
	if c.bad || c.at != len(d.data)-22 || n < 1 || n > 8 {
		return Projection{}, ErrInput
	}
	return out, nil
}
