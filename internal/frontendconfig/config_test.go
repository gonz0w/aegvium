package frontendconfig

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func descriptor(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("../requestctx/testdata/pair2_joint.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Hex string `json:"descriptor_hex"`
	}
	if json.Unmarshal(raw, &f) != nil {
		t.Fatal("public descriptor fixture")
	}
	out, err := hex.DecodeString(f.Hex)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestBundledFrontendFixedDataPath(t *testing.T) {
	d := descriptor(t)
	c, err := Compile(d, "front-a.internal.test", "192.0.2.30:443")
	if err != nil {
		t.Fatal("fixed descriptor refused")
	}
	raw := c.Bytes()
	text := string(raw)
	for _, want := range []string{
		"user _haproxy\n", "group _haproxy\n", "chroot /var/empty\n", "nbthread 1\n", "maxconn 4\n",
		"bind 192.0.2.30:443 ssl crt /etc/aegvium/frontend/public.pem",
		"server inspector 192.0.2.20:9443 ssl verify required ca-file /etc/aegvium/frontend/inspector-root.pem",
		"crt /etc/aegvium/frontend/frontend.pem sni str(inspect.internal.test)",
		"verifyhost inspect.internal.test alpn http/1.1 proto h1 ssl-min-ver TLSv1.3 ssl-max-ver TLSv1.3 no-ssl-reuse",
		"http-reuse never", "retries 0", "Aegvium-Contract M2-H1/3", "Aegvium-Generation 0123456789abcdef0123456789abcdef",
		"Aegvium-Connection %[var(sess.vw_remote)]:%[var(sess.vw_rport)]/%[var(sess.vw_local)]:%[var(sess.vw_lport)]",
	} {
		if !strings.Contains(text, want) {
			t.Fatal("closed frontend directive missing")
		}
	}
	if len(raw) > 32768 || c.Digest() != sha256.Sum256(raw) || strings.Count(text, "  server ") != 1 ||
		strings.Contains(text, "/etc/vectivium") || strings.Contains(text, "192.0.2.10:8443") ||
		strings.Contains(text, "daemon\n") || strings.Contains(text, "master-worker") || strings.Contains(text, "stats socket") {
		t.Fatal("frontend authority or bound changed")
	}
	guard := strings.Index(text, "tcp-request content switch-mode http proto h1")
	if guard < 0 || strings.Index(text, "http-request deny unless { req.ver") < guard ||
		strings.Index(text, "Aegvium-Connection") < guard || !strings.Contains(text, "http-request deny unless { http_first_req }") {
		t.Fatal("public prefix guard must precede parsed HTTP facts")
	}
	raw[0] ^= 1
	d[8] ^= 1
	if bytes.Equal(raw, c.Bytes()) || sha256.Sum256(c.Bytes()) != c.Digest() {
		t.Fatal("candidate aliases input or output")
	}
}

func TestBundledFrontendRefusesUnboundOrAmbiguousInput(t *testing.T) {
	d := descriptor(t)
	for _, input := range [][]byte{nil, d[:47], append(bytes.Clone(d), 0), make([]byte, 8193)} {
		if _, err := Compile(input, "front-a.internal.test", "192.0.2.30:443"); err == nil {
			t.Fatal("invalid descriptor admitted")
		}
	}
	for _, role := range []string{"", "front-c.internal.test", "front-a.internal.test\nuser root"} {
		if _, err := Compile(d, role, "192.0.2.30:443"); err == nil {
			t.Fatal("unbound role admitted")
		}
	}
	for _, listen := range []string{"", "0.0.0.0:443", "224.0.0.1:443", "255.255.255.255:443", "[::1]:443", "192.0.2.30:0", "192.0.2.30:0443", "192.0.2.10:8443", "192.0.2.20:9443", "192.0.2.30:443\ndaemon"} {
		if _, err := Compile(d, "front-a.internal.test", listen); err == nil {
			t.Fatal("unsafe or overlapping public endpoint admitted")
		}
	}
	old := bytes.Clone(d)
	old[6] = '1'
	copy(old[40:47], "M2-H1/1")
	if _, err := Compile(old, "front-a.internal.test", "192.0.2.30:443"); err == nil {
		t.Fatal("CONTROL-only descriptor acquired DATA")
	}
}

func TestBundledFrontendAllRoutesShareSameOwnerBinding(t *testing.T) {
	d := descriptor(t)
	// Independent retained serialization has one route from byte48 through the
	// fixed22-byte limits trailer. Add a sorted second route, then vary one fact.
	first := bytes.Clone(d[48 : len(d)-22])
	second := bytes.Replace(bytes.Clone(first), []byte("app.example.test"), []byte("web.example.test"), 1)
	second[1] = 'z' // app_primary -> zpp_primary.
	prefix := bytes.Clone(d[:48])
	prefix[47] = 2
	two := append(append(append(prefix, first...), second...), d[len(d)-22:]...)
	if _, e := Compile(two, "front-a.internal.test", "192.0.2.30:443"); e != nil {
		t.Fatal("common multi-route owner refused")
	}
	for _, changed := range [][]byte{
		bytes.Replace(second, []byte("front-a.internal.test"), []byte("front-c.internal.test"), 1),
		bytes.Replace(second, []byte("192.0.2.20"), []byte("192.0.2.21"), 1),
		bytes.Replace(second, []byte("inspect.internal.test"), []byte("another.internal.test"), 1),
	} {
		bad := append(append(append(bytes.Clone(prefix), first...), changed...), d[len(d)-22:]...)
		if _, e := Compile(bad, "front-a.internal.test", "192.0.2.30:443"); e == nil {
			t.Fatal("cross-route frontend binding spliced")
		}
	}
}
