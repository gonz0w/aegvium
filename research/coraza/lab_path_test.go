// SPDX-License-Identifier: BSD-3-Clause
package spike

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

type labPathReceipt struct {
	Case             string `json:"case"`
	Status           int    `json:"status"`
	Backend          int    `json:"backend"`
	BodySHA          string `json:"body_sha256"`
	HeadersClean     bool   `json:"headers_clean"`
	ClientError      bool   `json:"client_error"`
	BackendHost      string `json:"backend_host"`
	BackendAuthority string `json:"backend_authority"`
}

type labAckWriter struct {
	pending string
	events  chan string
}

func (w *labAckWriter) Write(data []byte) (int, error) {
	w.pending += string(data)
	if len(w.pending) > 1024 {
		return 0, errors.New("lab ack bound")
	}
	for {
		index := strings.IndexByte(w.pending, '\n')
		if index < 0 {
			break
		}
		line := w.pending[:index]
		w.pending = w.pending[index+1:]
		if line != "owned lab companion ready" && line != "owned lab reload accepted" && line != "owned lab reload rejected" {
			return 0, errors.New("unexpected lab diagnostic")
		}
		select {
		case w.events <- line:
		default:
			return 0, errors.New("lab ack queue bound")
		}
	}
	return len(data), nil
}

func TestLabCompanionPath(t *testing.T) {
	if runtime.GOOS != "openbsd" || os.Getenv("AEGVIUM_LAB_PATH") != "owned-guest" {
		t.Skip("owned OpenBSD executable/TLS path required")
	}
	if os.Geteuid() != 32767 {
		t.Fatal("fixture UID")
	}
	var mu sync.Mutex
	var receipts []labBackendReceipt
	control := &labBackendControl{}
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
			receipts = append(receipts, labBackendReceipt{string(data), clean, "app.test", r.Host})
			mu.Unlock()
			defer control.enter(r)()
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
	ca, validCert, wrongCert, untrustedCert := labTLSMaterial(t)
	var certMode atomic.Int32
	apiDone := make(chan error, 1)
	apiListener, e := net.Listen("tcp4", "127.0.0.1:18087")
	if e != nil {
		t.Fatal(e)
	}
	apiServer := &http.Server{ReadHeaderTimeout: time.Second, ErrorLog: log.New(io.Discard, "", 0), TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		switch certMode.Load() {
		case 1:
			return &wrongCert, nil
		case 2:
			return &untrustedCert, nil
		}
		return &validCert, nil
	}}, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		receipts = append(receipts, labBackendReceipt{string(data), clean, "api.test", r.Host})
		mu.Unlock()
		defer control.enter(r)()
		switch r.URL.Path {
		case "/large":
			io.WriteString(w, strings.Repeat("x", LabBodyLimit+1))
		case "/stall":
			w.WriteHeader(200)
			w.(http.Flusher).Flush()
			<-r.Context().Done()
		default:
			io.WriteString(w, "lab backend\n")
		}
	})}
	go func() { apiDone <- apiServer.Serve(tls.NewListener(apiListener, apiServer.TLSConfig)) }()
	apiRunning := true
	stopAPI := func() {
		if !apiRunning {
			return
		}
		apiRunning = false
		if e := apiServer.Close(); e != nil {
			t.Error(e)
		}
		if e := <-apiDone; e != http.ErrServerClosed {
			t.Error(e)
		}
	}
	defer stopAPI()
	config := LabConfig{Version: 1, Routes: []LabRoute{{Host: "app.test", Backend: "http://127.0.0.1:18086"}, {Host: "api.test", Backend: "https://127.0.0.1:18087", TLSServerName: "api.test", TLSCAFile: ca}}}
	configData, e := json.Marshal(config)
	if e != nil {
		t.Fatal(e)
	}
	configPath := filepath.Join(t.TempDir(), "routes.json")
	if e = os.WriteFile(configPath, configData, 0600); e != nil {
		t.Fatal(e)
	}
	runConfig := func(path string, check bool) error {
		args := []string{"-config", path}
		if check {
			args = append(args, "-check")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, "/var/aegvium-lab-proxy", args...)
		command.Env = []string{"PATH=/usr/bin:/bin", "AEGVIUM_LAB_PROXY=owned-guest"}
		return command.Run()
	}
	listenersAbsent := func() {
		for _, address := range []string{"127.0.0.1:18084", "127.0.0.1:18085"} {
			c, e := net.DialTimeout("tcp4", address, 100*time.Millisecond)
			if e == nil {
				c.Close()
				t.Fatal("config validation bound listener")
			}
		}
	}
	if e = runConfig(configPath, true); e != nil {
		t.Fatal("valid config check failed", e)
	}
	listenersAbsent()
	invalid := []string{strings.Replace(string(configData), `"version":1`, `"version":2`, 1), strings.Replace(string(configData), `"version":1`, `"version":1,"version":1`, 1), string(configData) + `{}`, strings.Replace(string(configData), "127.0.0.1:18086", "192.0.2.1:18086", 1), strings.Replace(string(configData), "app.test", "api.test", 1), strings.Replace(string(configData), "tls_ca_file", "unrecognized", 1), strings.Replace(string(configData), ca, ca+"missing", 1)}
	for i, data := range invalid {
		path := filepath.Join(filepath.Dir(configPath), fmt.Sprintf("bad-%d.json", i))
		if e = os.WriteFile(path, []byte(data), 0600); e != nil {
			t.Fatal(e)
		}
		e = runConfig(path, false)
		exit, ok := e.(*exec.ExitError)
		if !ok || exit.ExitCode() != 2 {
			t.Fatal("invalid config did not reject before startup", i, e)
		}
		listenersAbsent()
	}
	caData, e := os.ReadFile(ca)
	if e != nil {
		t.Fatal(e)
	}
	t.Logf("LAB-CONFIG {\"checked\":true,\"invalid_rejected\":%d,\"listeners_absent\":true,\"config_sha256\":\"%x\",\"ca_sha256\":\"%x\"}", len(invalid), sha256.Sum256(configData), sha256.Sum256(caData))
	command := exec.Command("/var/aegvium-lab-proxy", "-config", configPath)
	command.Env = []string{"PATH=/usr/bin:/bin", "AEGVIUM_LAB_PROXY=owned-guest"}
	events := make(chan string, 16)
	command.Stdout = &labAckWriter{events: events}
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
	expectEvent := func(want string) {
		select {
		case got := <-events:
			if got != want {
				t.Fatalf("lab completion got%q want%q", got, want)
			}
		case <-time.After(8 * time.Second):
			t.Fatal("lab completion deadline")
		}
	}
	expectEvent("owned lab companion ready")
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
	trace := newLabTransportTrace()
	var healthSamples atomic.Int32
	var healthLatestMS atomic.Int64
	request := func(name string, c *http.Client, method, path, host, media, body string, extra http.Header) (int, bool) {
		call, err := trace.begin(name)
		if err != nil {
			t.Fatal("invalid transport diagnostic case")
		}
		finish := func(stage string, status int, cause error) {
			row, err := call.finish(stage, status, cause, healthSamples.Load(), healthLatestMS.Load())
			if err != nil {
				t.Fatal("invalid transport diagnostic completion")
			}
			raw, _ := json.Marshal(row)
			t.Log("LAB-TRANSPORT " + string(raw))
		}

		r, e := http.NewRequest(method, "https://127.0.0.1:18120"+path, strings.NewReader(body))
		if e != nil {
			t.Fatal("fixture request construction failed")
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
			finish("roundtrip", 0, e)
			return 0, true
		}
		defer response.Body.Close()
		data, e := io.ReadAll(io.LimitReader(response.Body, LabBodyLimit+1))
		if e != nil || len(data) > LabBodyLimit {
			if e == nil {
				e = errLabTraceBodyLimit
			}
			finish("body", response.StatusCode, e)
			t.Fatal("client response bound")
		}
		finish("complete", response.StatusCode, nil)
		if response.StatusCode == 503 && string(data) != "inspection busy\n" {
			t.Fatal("admission response changed")
		}
		if response.StatusCode == 502 && string(data) != "backend unavailable\n" {
			t.Fatal("upstream error leaked/changed")
		}
		return response.StatusCode, false
	}
	ready := false
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); {
		code, _ := request("readiness", client, "GET", "/probe", "unknown.test", "", "", nil)
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
			r.BackendHost = receipts[before].host
			r.BackendAuthority = receipts[before].authority
			wantHost := "app.test"
			if strings.HasPrefix(name, "api-") || strings.HasPrefix(name, "alt-") {
				wantHost = "api.test"
			}
			if r.BackendHost != wantHost {
				t.Error("wrong backend route")
			}
			wantAuthority := wantHost
			if strings.HasPrefix(name, "alt-") {
				wantAuthority = "alt.test"
			}
			if r.BackendAuthority != wantAuthority {
				t.Error("backend authority changed")
			}
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
			code, err := request(tc.name, client, tc.method, tc.path, tc.host, tc.media, tc.body, tc.extra)
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
			code, err := request(name, c, "GET", "/ok", "app.test", "", "", nil)
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
	apiCase := func(name, path, host, method, body string, status, delta int) {
		t.Run(name, func(t *testing.T) {
			mu.Lock()
			before := len(receipts)
			mu.Unlock()
			media := ""
			if method == "POST" {
				media = "application/json"
			}
			code, err := request(name, client, method, path, host, media, body, nil)
			emit(name, code, err, before, status, delta, body)
		})
	}
	apiCase("api-get", "/ok", "api.test", "GET", "", 200, 1)
	apiCase("api-json", "/body", "api.test", "POST", `{"payload":"ordinary"}`, 200, 1)
	apiCase("api-port", "/ok", "api.test:18120", "GET", "", 200, 1)
	apiCase("api-wrong-port", "/ok", "api.test:18087", "GET", "", 421, 0)
	apiCase("api-sql", "/?payload=%27+OR+1%3D1--", "api.test", "GET", "", 403, 0)
	certMode.Store(1)
	apiCase("api-wrong-cert", "/ok", "api.test", "GET", "", 502, 0)
	certMode.Store(2)
	apiCase("api-untrusted-cert", "/ok", "api.test", "GET", "", 502, 0)
	certMode.Store(0)
	apiCase("api-tls-recovery", "/ok", "api.test", "GET", "", 200, 1)
	apiCase("api-large", "/large", "api.test", "GET", "", 502, 1)
	apiCase("api-stall", "/stall", "api.test", "GET", "", 502, 1)
	apiCase("api-after-stall", "/ok", "api.test", "GET", "", 200, 1)
	stopAPI()
	plaintext, e := net.Listen("tcp4", "127.0.0.1:18087")
	if e != nil {
		t.Fatal(e)
	}
	plaintextServer := &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("TLS route forwarded to cleartext handler")
		w.WriteHeader(200)
	})}
	plainDone := make(chan error, 1)
	go func() { plainDone <- plaintextServer.Serve(plaintext) }()
	apiCase("api-cleartext", "/ok", "api.test", "GET", "", 502, 0)
	plaintextServer.Close()
	if e := <-plainDone; e != http.ErrServerClosed {
		t.Fatal(e)
	}
	apiServer = &http.Server{ReadHeaderTimeout: time.Second, ErrorLog: log.New(io.Discard, "", 0), TLSConfig: apiServer.TLSConfig, Handler: apiServer.Handler}
	apiListener, e = net.Listen("tcp4", "127.0.0.1:18087")
	if e != nil {
		t.Fatal(e)
	}
	apiRunning = true
	go func() { apiDone <- apiServer.Serve(tls.NewListener(apiListener, apiServer.TLSConfig)) }()
	apiCase("api-cleartext-recovery", "/ok", "api.test", "GET", "", 200, 1)
	// One continuously reused health connection, without reconnects. Keeping it
	// active avoids confusing the existing one-second idle guard with a rebind.
	healthConn, e := net.DialTimeout("tcp4", "127.0.0.1:18085", time.Second)
	if e != nil {
		t.Fatal(e)
	}
	healthStop := make(chan struct{})
	healthDone := make(chan error, 1)
	go func() {
		reader := bufio.NewReader(healthConn)
		for {
			healthConn.SetDeadline(time.Now().Add(time.Second))
			if _, e := fmt.Fprint(healthConn, "HEAD /ready HTTP/1.1\r\nHost: health.test\r\n\r\n"); e != nil {
				healthDone <- e
				return
			}
			response, e := http.ReadResponse(reader, &http.Request{Method: "HEAD"})
			if e != nil {
				healthDone <- e
				return
			}
			response.Body.Close()
			if response.StatusCode != 200 || response.Close {
				healthDone <- errors.New("health generation interrupted")
				return
			}
			healthLatestMS.Store(trace.elapsedMS())
			healthSamples.Add(1)
			select {
			case <-healthStop:
				healthDone <- nil
				return
			case <-time.After(100 * time.Millisecond):
			}
		}
	}()
	healthRunning := true
	stopHealth := func() {
		if !healthRunning {
			return
		}
		healthRunning = false
		close(healthStop)
		select {
		case e := <-healthDone:
			if e != nil {
				t.Error(e)
			}
		case <-time.After(2 * time.Second):
			t.Error("health observer did not join")
		}
		healthConn.Close()
	}
	defer stopHealth()
	accepted, rejected := 0, 0
	reload := func(data []byte, accept bool) {
		replacement := configPath + ".new"
		if e := os.WriteFile(replacement, data, 0600); e != nil {
			t.Fatal(e)
		}
		if e := os.Rename(replacement, configPath); e != nil {
			t.Fatal(e)
		}
		if e := command.Process.Signal(syscall.SIGHUP); e != nil {
			t.Fatal(e)
		}
		if accept {
			expectEvent("owned lab reload accepted")
			accepted++
		} else {
			expectEvent("owned lab reload rejected")
			rejected++
		}
		if e := command.Process.Signal(syscall.Signal(0)); e != nil {
			t.Fatal("companion process replaced/lost", e)
		}
	}
	reload([]byte(strings.Replace(string(configData), `"version":1`, `"version":2`, 1)), false)
	apiCase("api-reload-version", "/ok", "api.test", "GET", "", 200, 1)
	reload([]byte(strings.Replace(string(configData), "app.test", "api.test", 1)), false)
	apiCase("api-reload-duplicate", "/ok", "api.test", "GET", "", 200, 1)
	reload([]byte(strings.Replace(string(configData), ca, ca+"missing", 1)), false)
	apiCase("api-reload-ca", "/ok", "api.test", "GET", "", 200, 1)
	replacement := LabConfig{Version: 1, Routes: []LabRoute{config.Routes[0], {Host: "alt.test", Backend: "https://127.0.0.1:18087", TLSServerName: "api.test", TLSCAFile: ca}}}
	replacementData, e := json.Marshal(replacement)
	if e != nil {
		t.Fatal(e)
	}
	reload(replacementData, true)
	apiCase("alt-reload-get", "/ok", "alt.test", "GET", "", 200, 1)
	apiCase("alt-reload-json", "/body", "alt.test", "POST", `{"payload":"ordinary"}`, 200, 1)
	apiCase("alt-reload-sql", "/?payload=%27+OR+1%3D1--", "alt.test", "GET", "", 403, 0)
	apiCase("reload-removed-api", "/ok", "api.test", "GET", "", 421, 0)
	apiCase("reload-app-during", "/ok", "app.test", "GET", "", 200, 1)
	reload(configData, true)
	apiCase("api-reload-restored", "/ok", "api.test", "GET", "", 200, 1)
	apiCase("reload-alt-removed", "/ok", "alt.test", "GET", "", 421, 0)
	stopHealth()
	restored, e := os.ReadFile(configPath)
	if e != nil || string(restored) != string(configData) {
		t.Fatal("known-good file not restored")
	}
	if healthSamples.Load() < 5 {
		t.Fatal("insufficient persistent health samples")
	}
	t.Logf("LAB-RELOAD {\"accepted\":%d,\"rejected\":%d,\"health_samples\":%d,\"health_connection_preserved\":true,\"same_process\":true,\"restored_config_sha256\":\"%x\",\"replacement_config_sha256\":\"%x\"}", accepted, rejected, healthSamples.Load(), sha256.Sum256(configData), sha256.Sum256(replacementData))
	signalReload := func(data []byte) {
		path := configPath + ".load"
		if e := os.WriteFile(path, data, 0600); e != nil {
			t.Fatal(e)
		}
		if e := os.Rename(path, configPath); e != nil {
			t.Fatal(e)
		}
		if e := command.Process.Signal(syscall.SIGHUP); e != nil {
			t.Fatal(e)
		}
	}
	healthOnce := func() int {
		tr := &http.Transport{Proxy: nil, DisableKeepAlives: true}
		defer tr.CloseIdleConnections()
		client := &http.Client{Transport: tr, Timeout: time.Second}
		r, _ := http.NewRequest("HEAD", "http://127.0.0.1:18085/ready", nil)
		response, e := client.Do(r)
		if e != nil {
			t.Fatal(e)
		}
		response.Body.Close()
		return response.StatusCode
	}
	runLabWorkloads(t, labLoadFixture{control: control, mu: &mu, receipts: &receipts, request: func(method, path, host, media, body string) int {
		code, _ := request("load", client, method, path, host, media, body, nil)
		return code
	}, health: healthOnce, signalReload: signalReload, expectEvent: expectEvent, events: events, replacement: replacementData})
	apiCase("alt-load-available", "/ok", "alt.test", "GET", "", 200, 1)
	apiCase("load-api-removed", "/ok", "api.test", "GET", "", 421, 0)
	signalReload(configData)
	expectEvent("owned lab reload accepted")
	apiCase("api-load-restored", "/ok", "api.test", "GET", "", 200, 1)
	apiCase("load-alt-removed", "/ok", "alt.test", "GET", "", 421, 0)
	t.Run("backend-down", func(t *testing.T) {
		stopBackend()
		mu.Lock()
		before := len(receipts)
		mu.Unlock()
		code, err := request("backend-down", client, "GET", "/ok", "app.test", "", "", nil)
		emit("backend-down", code, err, before, 502, 0, "")
	})
	backend, backendDone = startBackend()
	backendRunning = true
	t.Run("backend-recovery", func(t *testing.T) {
		mu.Lock()
		before := len(receipts)
		mu.Unlock()
		code, err := request("backend-recovery", client, "GET", "/ok", "app.test", "", "", nil)
		emit("backend-recovery", code, err, before, 200, 1, "")
	})
	t.Run("companion-stop", func(t *testing.T) {
		stopCompanion()
		mu.Lock()
		before := len(receipts)
		mu.Unlock()
		code, err := request("companion-stop", client, "GET", "/ok", "app.test", "", "", nil)
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
	stopAPI()
	for _, address := range []string{"127.0.0.1:18086", "127.0.0.1:18087"} {
		c, e := net.DialTimeout("tcp4", address, 100*time.Millisecond)
		if e == nil {
			c.Close()
			t.Error("backend listener survived")
		}
	}
	t.Logf("LAB-TRANSPORT-FINAL calls=%d raw_errors=false", trace.next.Load())
	t.Log("LAB-FINAL companion-stopped backend-stopped listeners-absent")
}
