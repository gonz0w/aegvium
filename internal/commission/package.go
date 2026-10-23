// SPDX-License-Identifier: BSD-3-Clause
package commission

import (
	"encoding/hex"
	"strconv"
	"strings"
)

// PackageImage is equality data inside an independently authenticated package.
// Parsing does not authenticate a package, executable, loader or target owner.
type PackageImage struct {
	Name   string
	Size   int64
	Digest [32]byte
}

// ParsePackageImages accepts the fixed native recipe's three executable records.
// No path, optional member, extension field or executable selector is accepted.
func ParsePackageImages(raw []byte) ([]PackageImage, error) {
	if len(raw) > 320 {
		return nil, ErrPayload
	}
	lines := strings.Split(string(raw), "\n")
	if len(lines) != 5 || lines[0] != "AEGBIN1" || lines[4] != "" {
		return nil, ErrPayload
	}
	var out []PackageImage
	for i, name := range []string{"inspector", "supervisor", "frontend-owner"} {
		p := strings.Split(lines[i+1], " ")
		if len(p) != 3 || p[0] != name {
			return nil, ErrPayload
		}
		size, err := strconv.ParseInt(p[1], 10, 64)
		limit := MaxImageBytes
		if name == "supervisor" {
			limit = 1048576
		}
		digest, e := hex.DecodeString(p[2])
		if err != nil || size < 1 || size > limit || strconv.FormatInt(size, 10) != p[1] ||
			e != nil || len(digest) != 32 || hex.EncodeToString(digest) != p[2] {
			return nil, ErrPayload
		}
		image := PackageImage{Name: name, Size: size}
		copy(image.Digest[:], digest)
		out = append(out, image)
	}
	return out, nil
}
