// SPDX-License-Identifier: BSD-3-Clause
package spike

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

type labBackendReceipt struct {
	body            string
	clean           bool
	host, authority string
}
type labBackendControl struct {
	mu           sync.Mutex
	active, peak int
	hold         *labBackendHold
}
type labBackendHold struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (h *labBackendHold) close() { h.once.Do(func() { close(h.release) }) }
func (c *labBackendControl) enter(r *http.Request) func() {
	c.mu.Lock()
	c.active++
	if c.active > c.peak {
		c.peak = c.active
	}
	hold := c.hold
	c.mu.Unlock()
	if hold != nil && strings.HasPrefix(r.URL.Path, "/held/") {
		hold.entered <- struct{}{}
		select {
		case <-hold.release:
		case <-r.Context().Done():
		}
	}
	return func() { c.mu.Lock(); c.active--; c.mu.Unlock() }
}
func (c *labBackendControl) begin(t *testing.T) *labBackendHold {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.active != 0 {
		t.Fatal("prior backend work survived")
	}
	c.peak = 0
	c.hold = &labBackendHold{entered: make(chan struct{}, 4), release: make(chan struct{})}
	return c.hold
}

type labLoadEffect struct {
	Backend   string `json:"backend_host"`
	Authority string `json:"authority"`
	BodySHA   string `json:"body_sha256"`
	Clean     bool   `json:"headers_clean"`
}
type labLoadRow struct {
	Phase            string          `json:"phase"`
	Statuses         []int           `json:"statuses"`
	Backend          int             `json:"backend"`
	Peak             int             `json:"peak"`
	Active           int             `json:"active_after"`
	Effects          []labLoadEffect `json:"effects"`
	Health           int             `json:"health"`
	ReloadAccepted   int             `json:"reload_accepted"`
	AckBeforeRelease bool            `json:"ack_before_release"`
	Limit            int             `json:"limit"`
}

type labLoadFixture struct {
	control      *labBackendControl
	mu           *sync.Mutex
	receipts     *[]labBackendReceipt
	request      func(method, path, host, media, body string) int
	health       func() int
	signalReload func([]byte)
	expectEvent  func(string)
	events       chan string
	replacement  []byte
}

func runLabWorkloads(t *testing.T, f labLoadFixture) {
	type input struct{ method, path, host, body string }
	begin := func() (int, *labBackendHold) {
		f.mu.Lock()
		before := len(*f.receipts)
		f.mu.Unlock()
		return before, f.control.begin(t)
	}
	waitEntered := func(h *labBackendHold, n int) {
		for i := 0; i < n; i++ {
			select {
			case <-h.entered:
			case <-time.After(time.Second):
				h.close()
				t.Fatal("native held work deadline")
			}
		}
	}
	burst := func(inputs []input) chan int {
		done := make(chan int, len(inputs))
		for _, in := range inputs {
			go func() {
				media := ""
				if in.method == "POST" {
					media = "application/json"
				}
				done <- f.request(in.method, in.path, in.host, media, in.body)
			}()
		}
		return done
	}
	collect := func(done chan int, n int) []int {
		codes := make([]int, 0, n)
		for i := 0; i < n; i++ {
			select {
			case code := <-done:
				codes = append(codes, code)
			case <-time.After(5 * time.Second):
				t.Fatal("native work did not finish")
			}
		}
		sort.Ints(codes)
		return codes
	}
	emit := func(phase string, before int, codes []int, health, reload int, early bool, wantCodes []int, wantPeak int) {
		f.mu.Lock()
		records := append([]labBackendReceipt(nil), (*f.receipts)[before:]...)
		f.mu.Unlock()
		row := labLoadRow{Phase: phase, Statuses: codes, Backend: len(records), Effects: []labLoadEffect{}, Health: health, ReloadAccepted: reload, AckBeforeRelease: early, Limit: LabRequestLimit}
		f.control.mu.Lock()
		row.Peak = f.control.peak
		row.Active = f.control.active
		f.control.hold = nil
		f.control.mu.Unlock()
		for _, record := range records {
			digest := sha256.Sum256([]byte(record.body))
			row.Effects = append(row.Effects, labLoadEffect{record.host, record.authority, hex.EncodeToString(digest[:]), record.clean})
		}
		sort.Slice(row.Effects, func(i, j int) bool { return fmt.Sprint(row.Effects[i]) < fmt.Sprint(row.Effects[j]) })
		data, _ := json.Marshal(row)
		t.Logf("LAB-LOAD %s", data)
		if fmt.Sprint(codes) != fmt.Sprint(wantCodes) || row.Peak != wantPeak || row.Active != 0 || health != 200 || early {
			t.Error("native admission/lifecycle mismatch")
		}
	}
	t.Run("saturation", func(t *testing.T) {
		before, hold := begin()
		defer hold.close()
		done := burst([]input{{"GET", "/held/cap0", "app.test", ""}, {"GET", "/held/cap1", "app.test", ""}, {"GET", "/held/cap2", "api.test", ""}, {"GET", "/held/cap3", "api.test", ""}})
		waitEntered(hold, 4)
		fifth := f.request("GET", "/overflow", "app.test", "", "")
		health := f.health()
		hold.close()
		codes := collect(done, 4)
		codes = append(codes, fifth)
		sort.Ints(codes)
		emit("saturation", before, codes, health, 0, false, []int{200, 200, 200, 200, 503}, 4)
	})
	t.Run("mixed", func(t *testing.T) {
		before, hold := begin()
		defer hold.close()
		done := burst([]input{{"POST", "/held/mixed0", "app.test", `{"payload":"ordinary"}`}, {"POST", "/held/mixed1", "api.test", `{"payload":"ordinary"}`}, {"GET", "/?payload=%27+OR+1%3D1--", "app.test", ""}, {"GET", "/?payload=%27+OR+1%3D1--", "api.test", ""}})
		waitEntered(hold, 2)
		health := f.health()
		hold.close()
		emit("mixed", before, collect(done, 4), health, 0, false, []int{200, 200, 403, 403}, 2)
	})
	t.Run("inflight-reload", func(t *testing.T) {
		before, hold := begin()
		defer hold.close()
		done := burst([]input{{"GET", "/held/inflight", "api.test", ""}})
		waitEntered(hold, 1)
		f.signalReload(f.replacement)
		early := false
		select {
		case <-f.events:
			early = true
		case <-time.After(500 * time.Millisecond):
		}
		health := f.health()
		hold.close()
		codes := collect(done, 1)
		if !early {
			f.expectEvent("owned lab reload accepted")
		}
		emit("inflight-reload", before, codes, health, 1, early, []int{200}, 1)
	})
}

// Exercise the workload coordinator against the real admission/generation/WAF
// and owned HTTP/TLS backends before its separate native relayd/CLI run.
func TestLabWorkloadsHost(t *testing.T) {
	var mu sync.Mutex
	var receipts []labBackendReceipt
	control := &labBackendControl{}
	backend := func(name string) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			data, e := io.ReadAll(r.Body)
			if e != nil {
				t.Error(e)
				return
			}
			clean := true
			for _, key := range []string{"Forwarded", "X-Forwarded-For", "X-Real-IP", "X-Original-URL", "Proxy-Authorization"} {
				clean = clean && r.Header.Get(key) == ""
			}
			mu.Lock()
			receipts = append(receipts, labBackendReceipt{string(data), clean, name, r.Host})
			mu.Unlock()
			defer control.enter(r)()
			io.WriteString(w, "owned\n")
		})
	}
	plain := httptest.NewServer(backend("app.test"))
	defer plain.Close()
	ca, cert, _, _ := labTLSMaterial(t)
	secure := httptest.NewUnstartedServer(backend("api.test"))
	secure.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	secure.StartTLS()
	defer secure.Close()
	original := LabConfig{Version: 1, Routes: []LabRoute{{Host: "app.test", Backend: plain.URL}, {Host: "api.test", Backend: secure.URL, TLSServerName: "api.test", TLSCAFile: ca}}}
	proxy, e := StartLabProxy(LabProfile{DataAddress: "127.0.0.1:0", HealthAddress: "127.0.0.1:0", Ingress: netip.MustParseAddrPort("127.0.0.1:18120"), Routes: original.Routes})
	if e != nil {
		t.Fatal(e)
	}
	defer proxy.Close()
	replacement := LabConfig{Version: 1, Routes: []LabRoute{original.Routes[0], {Host: "alt.test", Backend: secure.URL, TLSServerName: "api.test", TLSCAFile: ca}}}
	data, e := json.Marshal(replacement)
	if e != nil {
		t.Fatal(e)
	}
	events := make(chan string, 1)
	runLabWorkloads(t, labLoadFixture{control: control, mu: &mu, receipts: &receipts, request: func(method, path, host, media, body string) int {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Host = host
		r.Header.Set("User-Agent", "Aegvium owned lab")
		r.Header.Set("Accept", "*/*")
		if media != "" {
			r.Header.Set("Content-Type", media)
		}
		w := httptest.NewRecorder()
		proxy.servers[0].Handler.ServeHTTP(w, r)
		return w.Code
	}, health: func() int {
		w := httptest.NewRecorder()
		proxy.servers[1].Handler.ServeHTTP(w, httptest.NewRequest("HEAD", "/ready", nil))
		return w.Code
	}, signalReload: func(data []byte) {
		config, e := ReadLabConfig(bytes.NewReader(data))
		if e != nil {
			t.Fatal(e)
		}
		go func() {
			if e := proxy.Reload(config.Routes); e != nil {
				t.Error(e)
				events <- "rejected"
			} else {
				events <- "owned lab reload accepted"
			}
		}()
	}, expectEvent: func(want string) {
		select {
		case got := <-events:
			if got != want {
				t.Error("reload outcome", got)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("host reload did not finish")
		}
	}, events: events, replacement: data})
}
