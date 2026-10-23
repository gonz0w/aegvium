// SPDX-License-Identifier: BSD-3-Clause
package commission

// ProductionInputs is only the closed source initializer's fixed directory
// inventory. It provides no filesystem, identity, freshness or launch authority.
func ProductionInputs(names []string, mode []byte) bool {
	want := map[string]bool{"pair.snapshot": true, "frontend-mode": true, "roles": true}
	switch string(mode) {
	case "bundled\n":
		want["frontend"] = true
	case "external\n":
	default:
		return false
	}
	if len(names) != len(want) {
		return false
	}
	for _, name := range names {
		if !want[name] {
			return false
		}
		delete(want, name)
	}
	return len(want) == 0
}
