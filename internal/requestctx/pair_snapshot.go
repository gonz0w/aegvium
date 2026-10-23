// SPDX-License-Identifier: BSD-3-Clause
package requestctx

import (
	"crypto/sha256"
	"errors"

	"github.com/gonz0w/aegvium/internal/pairmodel"
)

var errPair = errors.New("unavailable pair preparation")

type pairedSnapshot struct {
	context             *Snapshot
	tuple               [104]byte
	serverName, address string
	port                uint16
	dataAddress         string
	dataPort            uint16
	serverAnchor        [32]byte
	roles               map[string]map[[32]byte]bool
	anchors             map[[32]byte]bool
}

// Builds owned configuration from validated bytes; no history/auth/Ready claim.
func newPairedSnapshot(input []byte) (*pairedSnapshot, error) {
	d, err := pairmodel.Parse(input)
	if err != nil {
		return nil, errPair
	}
	p, err := d.Projection()
	if err != nil || len(p.Routes) == 0 {
		return nil, errPair
	}
	first := p.Routes[0]
	s := &pairedSnapshot{serverName: first.InspectorName, address: first.InspectorAddress, port: first.InspectorPort, dataAddress: first.DataAddress, dataPort: first.DataPort, serverAnchor: first.ServerAnchor, roles: make(map[string]map[[32]byte]bool), anchors: make(map[[32]byte]bool)}
	routes := make([]Route, 0, len(p.Routes))
	for _, r := range p.Routes {
		if r.InspectorName != s.serverName || r.InspectorAddress != s.address || r.InspectorPort != s.port || r.ServerAnchor != s.serverAnchor || r.DataAddress != s.dataAddress || r.DataPort != s.dataPort || p.Profile == "M2-H1/3" && r.FrontendAnchor != first.FrontendAnchor {
			return nil, errPair
		}
		routes = append(routes, Route{ID: r.ID, PublicName: r.PublicName, Port: r.PublicPort, PolicyPin: r.PolicyPin, FrontendPeers: r.FrontendPeers})
		for _, name := range r.FrontendPeers {
			if name == s.serverName {
				return nil, errPair
			}
			if s.roles[name] == nil {
				s.roles[name] = make(map[[32]byte]bool)
			}
			s.roles[name][r.FrontendAnchor] = true
		}
		s.anchors[r.FrontendAnchor] = true
	}
	s.context, err = newSnapshotProfile(p.Generation, routes, p.Profile)
	if err != nil {
		return nil, errPair
	}
	common := sha256.Sum256(d.Bytes())
	contract := sha256.Sum256([]byte(p.Profile))
	copy(s.tuple[:8], "AGCHECK1")
	copy(s.tuple[8:40], p.Generation)
	copy(s.tuple[40:72], common[:])
	copy(s.tuple[72:], contract[:])
	return s, nil
}
