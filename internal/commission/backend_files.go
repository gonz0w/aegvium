// SPDX-License-Identifier: BSD-3-Clause
package commission

import (
	"encoding/hex"
	"sort"

	"github.com/gonz0w/aegvium/internal/backendconfig"
)

// BackendFiles is exact private placement data, never application authority.
func BackendFiles(descriptor, configuration []byte) ([]RoleFile, error) {
	c, e := backendconfig.Parse(configuration, descriptor)
	if e != nil {
		return nil, ErrPayload
	}
	out := []RoleFile{{Name: "backend.conf", Limit: 8192}, {Name: "backend-cert.pem", Limit: 65536}, {Name: "backend-key.pem", Limit: 16384}, {Name: "backend-client-root.der", Limit: 16384, Anchor: c.ClientAnchor}}
	byName := make(map[string][32]byte)
	for _, route := range c.Routes {
		byName["backend-"+hex.EncodeToString(route.ServerAnchor[:])+".der"] = route.ServerAnchor
	}
	var names []string
	for name := range byName {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		out = append(out, RoleFile{Name: name, Limit: 16384, Anchor: byName[name]})
	}
	return out, nil
}
