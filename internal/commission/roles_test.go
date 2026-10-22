// SPDX-License-Identifier: BSD-3-Clause
package commission

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestRoleFilesExactDescriptorBoundPlacement(t *testing.T) {
	d, _, _ := fixture(t) // Retained public descriptor; no credentials.
	files, e := RoleFiles(d)
	if e != nil || len(files) != 4 {
		t.Fatal("fixed role set refused")
	}
	names := []string{"cert.pem", "key.pem", "server.der", "client-fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0.der"}
	for i, file := range files {
		if file.Name != names[i] || file.Limit != []int64{65536, 16384, 16384, 16384}[i] {
			t.Fatal("role path or bound changed")
		}
	}
	if hex.EncodeToString(files[2].Anchor[:]) != "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" ||
		hex.EncodeToString(files[3].Anchor[:]) != "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0" {
		t.Fatal("anchor not descriptor bound")
	}
	d[len(d)-86] ^= 1
	if files[2].Anchor[0] != 0 {
		t.Fatal("role plan aliases caller bytes")
	}
	for _, bad := range [][]byte{nil, d[:46], append(bytes.Clone(d), 0), make([]byte, 8193)} {
		if _, e := RoleFiles(bad); e == nil {
			t.Fatal("invalid descriptor selected role files")
		}
	}
}

func TestBackendFilesExactPrivatePlacement(t *testing.T) {
	d, _, _ := fixture(t)
	raw, e := os.ReadFile("../backendconfig/testdata/binding.json")
	if e != nil {
		t.Fatal(e)
	}
	var f struct {
		Hex string `json:"backend_hex"`
	}
	if json.Unmarshal(raw, &f) != nil {
		t.Fatal("invalid public literal")
	}
	b, e := hex.DecodeString(f.Hex)
	if e != nil {
		t.Fatal(e)
	}
	files, e := BackendFiles(d, b)
	want := []string{"backend.conf", "backend-cert.pem", "backend-key.pem", "backend-client-root.der", "backend-404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f.der"}
	if e != nil || len(files) != len(want) {
		t.Fatal("private placement refused")
	}
	for i, file := range files {
		if file.Name != want[i] || file.Limit != []int64{8192, 65536, 16384, 16384, 16384}[i] {
			t.Fatal("private path or cap changed")
		}
	}
	if files[3].Anchor[0] != 32 || files[3].Anchor[31] != 63 || files[4].Anchor[0] != 64 || files[4].Anchor[31] != 95 {
		t.Fatal("private anchor not config bound")
	}
	b[40] ^= 1
	if _, e := BackendFiles(d, b); e == nil {
		t.Fatal("foreign pairing selected private files")
	}
}
