// SPDX-License-Identifier: BSD-3-Clause
package commission

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"testing"
)

func frontendDescriptor(t *testing.T) []byte {
	t.Helper()
	raw, e := os.ReadFile("../requestctx/testdata/pair2_joint.json")
	if e != nil {
		t.Fatal(e)
	}
	var f struct {
		Hex string `json:"descriptor_hex"`
	}
	if json.Unmarshal(raw, &f) != nil {
		t.Fatal("public fixture")
	}
	d, e := hex.DecodeString(f.Hex)
	if e != nil {
		t.Fatal(e)
	}
	return d
}

func TestFrontendFilesStaySeparateAndDescriptorBound(t *testing.T) {
	d := frontendDescriptor(t)
	candidate, files, e := FrontendFiles(d, "front-a.internal.test", "192.0.2.30:443")
	if e != nil || len(files) != 5 || len(candidate.Bytes()) == 0 {
		t.Fatal("frontend source plan refused")
	}
	names := []string{"public.pem", "frontend.pem", "inspector-root.pem", "server.der", "client.der"}
	limits := []int64{81920, 81920, 32768, 16384, 16384}
	for i, f := range files {
		if f.Name != names[i] || f.Limit != limits[i] {
			t.Fatal("frontend role path or bound changed")
		}
	}
	if files[3].Anchor[0] != 0 || files[3].Anchor[31] != 31 || files[4].Anchor[0] != 255 || files[4].Anchor[31] != 224 {
		t.Fatal("frontend roots not bound to full descriptor")
	}
	old, _, _ := fixture(t)
	if _, _, e := FrontendFiles(old, "front-a.internal.test", "192.0.2.30:443"); e == nil {
		t.Fatal("AGPAIR1 acquired a bundled DATA frontend")
	}
}

func TestMatchFrontendRootUsesExactOpaqueDerNotAProof(t *testing.T) {
	// Opaque synthetic bytes, not a certificate/key, parser or credential fixture.
	der := []byte("synthetic opaque root bytes")
	raw := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	anchor := sha256.Sum256(der)
	if !MatchFrontendRoot(raw, der, anchor) {
		t.Fatal("canonical equality refused")
	}
	for _, bad := range [][]byte{nil, append([]byte("prefix"), raw...), append(bytes.Clone(raw), raw...), append(bytes.Clone(raw), '\n'), bytes.Replace(raw, []byte("CERTIFICATE"), []byte("PRIVATE KEY"), -1)} {
		if MatchFrontendRoot(bad, der, anchor) {
			t.Fatal("nonexact root material accepted")
		}
	}
	if MatchFrontendRoot(raw, append(bytes.Clone(der), 'x'), anchor) || MatchFrontendRoot(raw, der, [32]byte{}) {
		t.Fatal("foreign root accepted")
	}
}
