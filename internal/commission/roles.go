// SPDX-License-Identifier: BSD-3-Clause
package commission

import (
	"encoding/hex"
	"sort"

	"github.com/gonz0w/aegvium/internal/pairmodel"
)

// RoleFile is fixed placement policy, not credentials, freshness or authority.
// Only the owning first-image builder may supply the corresponding bytes.
type RoleFile struct {
	Name   string
	Limit  int64
	Anchor [32]byte // Nonzero only for an exact descriptor-bound DER anchor.
}

func RoleFiles(descriptor []byte) ([]RoleFile, error) {
	d, err := pairmodel.Parse(descriptor)
	if err != nil {
		return nil, ErrPayload
	}
	p, err := d.Projection()
	if err != nil || len(p.Routes) == 0 {
		return nil, ErrPayload
	}
	first := p.Routes[0]
	anchors := make(map[[32]byte]bool)
	for _, r := range p.Routes {
		if r.InspectorAddress != first.InspectorAddress || r.InspectorPort != first.InspectorPort || r.InspectorName != first.InspectorName || r.ServerAnchor != first.ServerAnchor || r.DataAddress != first.DataAddress || r.DataPort != first.DataPort || p.Profile == "M2-H1/3" && r.FrontendAnchor != first.FrontendAnchor {
			return nil, ErrPayload
		}
		anchors[r.FrontendAnchor] = true
	}
	if len(anchors) < 1 || len(anchors) > 8 {
		return nil, ErrPayload
	}
	out := []RoleFile{{Name: "cert.pem", Limit: 65536}, {Name: "key.pem", Limit: 16384}, {Name: "server.der", Limit: 16384, Anchor: first.ServerAnchor}}
	var names []string
	byName := make(map[string][32]byte)
	for anchor := range anchors {
		name := "client-" + hex.EncodeToString(anchor[:]) + ".der"
		names = append(names, name)
		byName[name] = anchor
	}
	sort.Strings(names)
	for _, name := range names {
		out = append(out, RoleFile{Name: name, Limit: 16384, Anchor: byName[name]})
	}
	return out, nil
}
