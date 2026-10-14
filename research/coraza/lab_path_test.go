// SPDX-License-Identifier: BSD-3-Clause
package spike

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

type labPathReceipt struct {
	Case         string `json:"case"`
	Status       int    `json:"status"`
	Backend      int    `json:"backend"`
	BodySHA      string `json:"body_sha256"`
	HeadersClean bool   `json:"headers_clean"`
	ClientError  bool   `json:"client_error"`
}

func TestLabCompanionPath(t *testing.T) {
	if runtime.GOOS != "openbsd" || os.Getenv("AEGVIUM_LAB_PATH") != "owned-guest" {
		t.Skip("owned OpenBSD executable/TLS path required")
	}
	if os.Geteuid() != 32767 {
		t.Fatal("fixture UID")
	}
	var mu sync.Mutex
	type receipt struct {
		body  string
		clean bool
	}
	var receipts []receipt
	startBackend := func() (*http.Server, chan error) {
		listener, e := net.Listen("tcp4", "127.0.0.1:18086")
		if e != nil {
			t.Fatal(e)
		}
		s := &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/_alive" {
				_, _ = io.WriteString(w, "backend alive\n")
				return
			}
			data, e := io.ReadAll(io.LimitReader(r.Body, LabBodyLimit+1))
			if e != nil {
				http.Error(w, "read failed", 500)
				return
			}
			clean := true
			for _, k := range []string{"Forwarded", "X-Forwarded-For", "X-Real-IP", "X-Original-URL", "Proxy-Authorization"} {
				clean = clean && r.Header.Get(k) == ""
			}
			mu.Lock()
			receipts = append(receipts, receipt{string(data), clean})
			mu.Unlock()
			_, _ = io.WriteString(w, "lab backend\n")
		})}
		done := make(chan error, 1)
		go func() { done <- s.Serve(listener) }()
		return s, done
	}
	backend, backendDone := startBackend()
	backendRunning := true
	stopBackend := func() {
		if !backendRunning {
			return
		}
		backendRunning = false
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if e := backend.Shutdown(ctx); e != nil {
			t.Error(e)
			backend.Close()
		}
		if e := <-backendDone; e != http.ErrServerClosed {
			t.Error(e)
		}
	}
	defer stopBackend()
	command := exec.Command("/var/aegvium-lab-proxy")
	command.Env = []string{"PATH=/usr/bin:/bin", "AEGVIUM_LAB_PROXY=owned-guest"}
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if e := command.Start(); e != nil {
		t.Fatal(e)
	}
	exited := make(chan error, 1)
	go func() { exited <- command.Wait() }()
	running := true
	stopCompanion := func() {
		if !running {
			return
		}
		running = false
		if e := command.Process.Signal(syscall.SIGTERM); e != nil {
			t.Error(e)
		}
		select {
		case e := <-exited:
			if e != nil {
				t.Error(e)
			}
		case <-time.After(8 * time.Second):
			t.Error("companion did not drain")
			command.Process.Kill()
			<-exited
		}
	}
	defer stopCompanion()
	cert, e := os.ReadFile("/etc/ssl/aegvium-lab.crt")
	if e != nil {
		t.Fatal(e)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(cert) {
		t.Fatal("CA parse")
	}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "app.test", MinVersion: tls.VersionTLS12}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request := func(c *http.Client, method, path, host, media, body string, extra http.Header) (int, bool) {
		r, e := http.NewRequest(method, "https://127.0.0.1:18120"+path, strings.NewReader(body))
		if e != nil {
			t.Fatal(e)
		}
		r.Host = host
		r.Header.Set("Accept", "*/*")
		r.Header.Set("User-Agent", "Aegvium owned lab")
		if media != "" {
			r.Header.Set("Content-Type", media)
		}
		for k, v := range extra {
			r.Header[k] = v
		}
		response, e := c.Do(r)
		if e != nil {
			return 0, true
		}
		defer response.Body.Close()
		data, e := io.ReadAll(io.LimitReader(response.Body, LabBodyLimit+1))
		if e != nil || len(data) > LabBodyLimit {
			t.Fatal("client response bound")
		}
		return response.StatusCode, false
	}
	ready := false
	for i := 0; i < 40; i++ {
		code, _ := request(client, "GET", "/probe", "unknown.test", "", "", nil)
		if code == 421 {
			ready = true
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !ready {
		t.Fatal("TLS/inspection ready deadline")
	}
	emit := func(name string, status int, clientError bool, before int, wantStatus, wantDelta int, wantBody string) {
		mu.Lock()
		defer mu.Unlock()
		delta := len(receipts) - before
		r := labPathReceipt{Case: name, Status: status, Backend: delta, HeadersClean: true, ClientError: clientError}
		if delta == 1 {
			sum := sha256.Sum256([]byte(receipts[before].body))
			r.BodySHA = hex.EncodeToString(sum[:])
			r.HeadersClean = receipts[before].clean
			if receipts[before].body != wantBody {
				t.Error("backend bytes changed")
			}
		}
		data, _ := json.Marshal(r)
		t.Logf("LAB-PATH %s", data)
		if status != wantStatus || delta != wantDelta || !r.HeadersClean {
			t.Errorf("path outcome %s want %d/%d", data, wantStatus, wantDelta)
		}
	}
	cases := []struct {
		name, method, path, host, media, body string
		extra                                 http.Header
		status, delta                         int
	}{
		{"get", "GET", "/ok", "app.test", "", "", nil, 200, 1}, {"json", "POST", "/body", "app.test", "application/json", `{"payload":"ordinary"}`, nil, 200, 1},
		{"sql", "GET", "/?payload=%27+OR+1%3D1--", "app.test", "", "", nil, 403, 0}, {"script", "POST", "/body", "app.test", "application/json", `{"payload":"<script>alert(1)</script>"}`, nil, 403, 0},
		{"unknown", "GET", "/ok", "other.test", "", "", nil, 421, 0}, {"oversize", "POST", "/body", "app.test", "application/json", strings.Repeat("x", LabBodyLimit+1), nil, 413, 0},
		{"media", "POST", "/body", "app.test", "text/plain", "ordinary", nil, 415, 0}, {"upgrade", "GET", "/ok", "app.test", "", "", http.Header{"Connection": {"Upgrade"}, "Upgrade": {"websocket"}}, 501, 0},
		{"spoof", "GET", "/ok", "app.test", "", "", http.Header{"Forwarded": {"for=192.0.2.99"}, "X-Forwarded-For": {"192.0.2.99"}, "X-Real-IP": {"192.0.2.99"}, "X-Original-Url": {"/hidden"}, "Proxy-Authorization": {"synthetic"}}, 200, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mu.Lock()
			before := len(receipts)
			mu.Unlock()
			code, err := request(client, tc.method, tc.path, tc.host, tc.media, tc.body, tc.extra)
			emit(tc.name, code, err, before, tc.status, tc.delta, tc.body)
		})
	}
	for _, name := range []string{"untrusted-cert", "wrong-name"} {
		t.Run(name, func(t *testing.T) {
			config := transport.TLSClientConfig.Clone()
			if name == "untrusted-cert" {
				config.RootCAs = x509.NewCertPool()
			} else {
				config.ServerName = "wrong.test"
			}
			tr := &http.Transport{Proxy: nil, DisableKeepAlives: true, TLSClientConfig: config}
			defer tr.CloseIdleConnections()
			c := &http.Client{Transport: tr, Timeout: 2 * time.Second}
			mu.Lock()
			before := len(receipts)
			mu.Unlock()
			code, err := request(c, "GET", "/ok", "app.test", "", "", nil)
			if !err {
				t.Error("unverified TLS accepted")
			}
			emit(name, code, err, before, 0, 0, "")
		})
	}
	t.Run("bare-data", func(t *testing.T) {
		mu.Lock()
		before := len(receipts)
		mu.Unlock()
		c, e := net.DialTimeout("tcp4", "127.0.0.1:18084", time.Second)
		if e != nil {
			t.Fatal(e)
		}
		c.SetDeadline(time.Now().Add(2 * time.Second))
		_, _ = fmt.Fprint(c, "GET /ok HTTP/1.1\r\nHost: app.test\r\n\r\n")
		data := make([]byte, 1)
		n, e := c.Read(data)
		c.Close()
		if n != 0 || e == nil {
			t.Error("bare prefix accepted")
		}
		emit("bare-data", 0, true, before, 0, 0, "")
	})
	t.Run("backend-down", func(t *testing.T) {
		stopBackend()
		mu.Lock()
		before := len(receipts)
		mu.Unlock()
		code, err := request(client, "GET", "/ok", "app.test", "", "", nil)
		emit("backend-down", code, err, before, 502, 0, "")
	})
	backend, backendDone = startBackend()
	backendRunning = true
	t.Run("backend-recovery", func(t *testing.T) {
		mu.Lock()
		before := len(receipts)
		mu.Unlock()
		code, err := request(client, "GET", "/ok", "app.test", "", "", nil)
		emit("backend-recovery", code, err, before, 200, 1, "")
	})
	t.Run("companion-stop", func(t *testing.T) {
		stopCompanion()
		mu.Lock()
		before := len(receipts)
		mu.Unlock()
		code, err := request(client, "GET", "/ok", "app.test", "", "", nil)
		if code >= 200 && code < 400 {
			t.Error("forwarded after stop")
		}
		emit("companion-stop", code, err, before, code, 0, "")
		for _, addr := range []string{"127.0.0.1:18084", "127.0.0.1:18085"} {
			c, e := net.DialTimeout("tcp4", addr, 100*time.Millisecond)
			if e == nil {
				c.Close()
				t.Error("companion listener survived")
			}
		}
		proof, e := (&http.Client{Timeout: time.Second}).Get("http://127.0.0.1:18086/_alive")
		if e != nil {
			t.Fatal(e)
		}
		b, e := io.ReadAll(io.LimitReader(proof.Body, 32))
		proof.Body.Close()
		if e != nil || proof.StatusCode != 200 || string(b) != "backend alive\n" {
			t.Fatal("backend not alive")
		}
	})
	stopBackend()
	t.Log("LAB-FINAL companion-stopped backend-stopped listeners-absent")
}
