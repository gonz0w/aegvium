// SPDX-License-Identifier: BSD-3-Clause
package commission

import (
	"bytes"
	"crypto/sha256"
	"encoding/pem"

	"github.com/gonz0w/aegvium/internal/frontendconfig"
)

// FrontendFiles is a closed offline input plan. Neither this data nor a rendered
// configuration creates frontend ownership, a package pin or launch authority.
func FrontendFiles(descriptor []byte, role, listen string) (frontendconfig.Candidate, []RoleFile, error) {
	c, err := frontendconfig.Compile(descriptor, role, listen)
	if err != nil {
		return frontendconfig.Candidate{}, nil, ErrPayload
	}
	server, client := c.Anchors()
	return c, []RoleFile{
		{Name: "public.pem", Limit: 81920},
		{Name: "frontend.pem", Limit: 81920},
		{Name: "inspector-root.pem", Limit: 32768},
		{Name: "server.der", Limit: 16384, Anchor: server},
		{Name: "client.der", Limit: 16384, Anchor: client},
	}, nil
}

// MatchFrontendRoot checks only exact opaque DER/PEM equality and the descriptor
// digest. Certificate validity, EKU, key pairing and live TLS remain loader gates.
func MatchFrontendRoot(raw, der []byte, anchor [32]byte) bool {
	block, rest := pem.Decode(raw)
	return len(raw) > 0 && len(raw) <= 32768 && len(der) > 0 && len(der) <= 16384 &&
		block != nil && block.Type == "CERTIFICATE" && len(block.Headers) == 0 &&
		bytes.Equal(raw, pem.EncodeToMemory(block)) && len(rest) == 0 &&
		bytes.Equal(block.Bytes, der) && sha256.Sum256(der) == anchor
}
