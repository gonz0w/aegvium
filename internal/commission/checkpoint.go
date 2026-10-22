// SPDX-License-Identifier: BSD-3-Clause
package commission

import "bytes"

// InitialMatches checks staging bytes against the same initial format emitted
// by Write. Equality creates no fresh-image, current-owner or cleanup authority.
func InitialMatches(generation, state []byte) bool {
	want, err := initialState(generation)
	return err == nil && bytes.Equal(state, want[:])
}
