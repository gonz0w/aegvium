// SPDX-License-Identifier: BSD-3-Clause
package spike

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Private keys stay in fixture memory, never config, logs or evidence.
func labTLSMaterial(t *testing.T) (string, tls.Certificate, tls.Certificate, tls.Certificate) {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "owned lab CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, e := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(t.TempDir(), "ca.pem")
	if e = os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); e != nil {
		t.Fatal(e)
	}
	makeCert := func(serial int64, name string, self bool) tls.Certificate {
		private, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		cert := &x509.Certificate{SerialNumber: big.NewInt(serial), DNSNames: []string{name}, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		parent, signer := ca, key
		if self {
			parent, signer = cert, private
		}
		der, e := x509.CreateCertificate(rand.Reader, cert, parent, &private.PublicKey, signer)
		if e != nil {
			t.Fatal(e)
		}
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: private}
	}
	return path, makeCert(2, "api.test", false), makeCert(3, "wrong.test", false), makeCert(4, "api.test", true)
}

func TestLabConfigRejectsUnsafeInputs(t *testing.T) {
	good := `{"version":1,"routes":[{"host":"app.test","backend":"http://127.0.0.1:18086"}]}`
	if _, e := ReadLabConfig(strings.NewReader(good)); e != nil {
		t.Fatal(e)
	}
	cases := map[string]string{
		"duplicate-key": strings.Replace(good, `"version":1`, `"version":1,"version":1`, 1),
		"folded-key":    strings.Replace(good, "version", "Version", 1),
		"unknown-field": strings.Replace(good, `"version":1`, `"version":1,"ignored":true`, 1),
		"unknown-route": strings.Replace(good, `"host":"app.test"`, `"host":"app.test","ignored":true`, 1),
		"folded-route":  strings.Replace(good, "backend", "Backend", 1),
		"trailing":      good + `{}`, "oversized": strings.Repeat(" ", LabConfigLimit) + good,
		"version": strings.Replace(good, `"version":1`, `"version":2`, 1), "empty": `{"version":1,"routes":[]}`,
		"duplicate-host": `{"version":1,"routes":[{"host":"app.test","backend":"http://127.0.0.1:18086"},{"host":"app.test","backend":"http://127.0.0.1:18087"}]}`,
		"public-host":    strings.Replace(good, "app.test", "example.com", 1), "host-port": strings.Replace(good, "app.test", "app.test:18120", 1),
		"wildcard": strings.Replace(good, "app.test", "*.test", 1), "folded-host": strings.Replace(good, "app.test", "App.test", 1),
		"null": `null`, "null-route": `{"version":1,"routes":[null]}`,
	}
	for _, backend := range []string{"http://example.test:18086", "http://192.0.2.1:18086", "http://127.0.0.1:80", "http://127.0.0.1:18084", "http://127.0.0.1:18085", "http://127.0.0.1:18120", "http://127.0.0.1:18086/", "http://user@127.0.0.1:18086", "http://127.0.0.1:18086?", "http://127.0.0.1:18086#", "ftp://127.0.0.1:18086", "https://127.0.0.1:18086"} {
		cases[backend] = strings.Replace(good, "http://127.0.0.1:18086", backend, 1)
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if _, e := ReadLabConfig(strings.NewReader(data)); e == nil {
				t.Fatal("unsafe config accepted")
			}
		})
	}
}

func TestLabConfiguredDispatchAndTLS(t *testing.T) {
	hosts := make(chan string, 4)
	receive := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		hosts <- r.Host + " " + string(data)
		io.WriteString(w, "owned\n")
	})
	plain := httptest.NewServer(receive)
	defer plain.Close()
	ca, cert, _, _ := labTLSMaterial(t)
	secure := httptest.NewUnstartedServer(receive)
	secure.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	secure.StartTLS()
	defer secure.Close()
	routes := []LabRoute{{Host: "app.test", Backend: plain.URL}, {Host: "api.test", Backend: secure.URL, TLSServerName: "api.test", TLSCAFile: ca}}
	handler, transports, waf, e := labConfiguredHandler(routes, labDirectives)
	if e != nil {
		t.Fatal(e)
	}
	defer waf.Close()
	defer func() {
		for _, tr := range transports {
			tr.CloseIdleConnections()
		}
	}()
	for _, host := range []string{"app.test", "api.test:18120", "unknown.test", "api.test:12345"} {
		r := httptest.NewRequest("POST", "/body", strings.NewReader(`{"payload":"ordinary"}`))
		r.Host = host
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Accept", "*/*")
		r.Header.Set("User-Agent", "Aegvium owned lab")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		want := 200
		if host == "unknown.test" || host == "api.test:12345" {
			want = 421
		}
		if w.Code != want {
			t.Fatalf("%s status%d want%d", host, w.Code, want)
		}
	}
	if len(hosts) != 2 || <-hosts != `app.test {"payload":"ordinary"}` || <-hosts != `api.test {"payload":"ordinary"}` {
		t.Fatal("route authority/body changed")
	}
	route := routes[1]
	_, config, e := labRouteTarget(route)
	if e != nil || config.InsecureSkipVerify || config.RootCAs == nil || config.ServerName != "api.test" {
		t.Fatal("explicit TLS trust missing")
	}
	for _, change := range []LabRoute{{Host: "api.test", Backend: plain.URL, TLSServerName: "api.test", TLSCAFile: ca}, {Host: "api.test", Backend: secure.URL, TLSServerName: "example.com", TLSCAFile: ca}, {Host: "api.test", Backend: secure.URL, TLSServerName: "api.test", TLSCAFile: "relative.pem"}, {Host: "api.test", Backend: secure.URL, TLSServerName: "api.test", TLSCAFile: ca + "missing"}} {
		if _, _, e := labRouteTarget(change); e == nil {
			t.Fatal("bad TLS input accepted")
		}
	}
	if e := os.WriteFile(ca, []byte("not PEM"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, _, e := labRouteTarget(route); e == nil {
		t.Fatal("invalid PEM accepted")
	}
	link := filepath.Join(t.TempDir(), "link")
	if e := os.Symlink(ca, link); e != nil {
		t.Fatal(e)
	}
	if _, e := ReadLabFile(link, LabConfigLimit); e == nil {
		t.Fatal("symlink accepted")
	}
}
