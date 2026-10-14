// SPDX-License-Identifier: BSD-3-Clause
package spike

import (
	"bytes"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"testing"

	crs "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
	corazahttp "github.com/corazawaf/coraza/v3/http"
	"github.com/corazawaf/coraza/v3/types"
)

const bodyResearchCap = 128

// A constructed-request experiment only; transport deadlines remain external.
func boundedResearchBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		original := r.Body
		if original == nil {
			http.Error(w, "body required", 400)
			return
		}
		defer original.Close()
		media := r.Header.Values("Content-Type")
		if len(media) != 1 {
			http.Error(w, "unsupported media", 415)
			return
		}
		kind, params, err := mime.ParseMediaType(media[0])
		if err != nil || kind != "application/json" && kind != "application/x-www-form-urlencoded" {
			http.Error(w, "unsupported media", 415)
			return
		}
		for name, value := range params {
			if name != "charset" || !strings.EqualFold(value, "utf-8") {
				http.Error(w, "unsupported media", 415)
				return
			}
		}
		enc := r.Header.Values("Content-Encoding")
		if len(enc) > 1 || len(enc) == 1 && !strings.EqualFold(enc[0], "identity") {
			http.Error(w, "unsupported encoding", 415)
			return
		}
		if r.ContentLength > bodyResearchCap {
			http.Error(w, "body too large", 413)
			return
		}
		data, err := io.ReadAll(io.LimitReader(original, bodyResearchCap+1))
		if len(data) > bodyResearchCap {
			http.Error(w, "body too large", 413)
			return
		}
		if err != nil {
			http.Error(w, "body unavailable", 500)
			return
		}
		if r.ContentLength >= 0 && r.ContentLength != int64(len(data)) {
			http.Error(w, "body length mismatch", 400)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(data))
		next.ServeHTTP(w, r)
	})
}

type bodyResearchReader struct {
	reader        io.Reader
	bytes, closes int
}

func (r *bodyResearchReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	r.bytes += n
	return n, err
}
func (r *bodyResearchReader) Close() error { r.closes++; return nil }

func TestBoundedBodyAdmission(t *testing.T) {
	jsonSized := func(size int) string { return `{"payload":"` + strings.Repeat("x", size-len(`{"payload":""}`)) + `"}` }
	cases := []struct {
		name, media, body, encoding                      string
		length                                           int64
		fail                                             bool
		baseStatus, baseBackend, gateStatus, gateBackend int
	}{
		{"form-benign", "application/x-www-form-urlencoded", "payload=ordinary", "", -2, false, 200, 1, 200, 1},
		{"json-benign", "application/json", `{"payload":"ordinary"}`, "", -2, false, 200, 1, 200, 1},
		{"form-sql", "application/x-www-form-urlencoded", url.Values{"payload": {"' OR 1=1--"}}.Encode(), "", -2, false, 403, 0, 403, 0},
		{"json-script", "application/json", `{"payload":"<script>alert(1)</script>"}`, "", -2, false, 403, 0, 403, 0},
		{"exact-cap", "application/json", jsonSized(128), "", -2, false, 200, 1, 200, 1},
		{"declared-over", "application/json", jsonSized(129), "", -2, false, 200, 1, 413, 0},
		{"unknown-over", "application/json", jsonSized(129), "", -1, false, 200, 1, 413, 0},
		{"understated-over", "application/json", jsonSized(129), "", 16, false, 200, 1, 413, 0},
		{"invalid-json", "application/json", `{"payload":`, "", -2, false, 400, 0, 400, 0},
		{"text-media", "text/plain", "ordinary", "", -2, false, 403, 0, 415, 0},
		{"encoded-json", "application/json", `{"payload":"ordinary"}`, "gzip", -2, false, 403, 0, 415, 0},
		{"read-error", "application/x-www-form-urlencoded", "", "", -1, true, 200, 0, 500, 0},
		{"partial-read-error", "application/x-www-form-urlencoded", "", "", -1, true, 200, 0, 500, 0},
	}
	for _, profile := range []string{"baseline", "gated"} {
		t.Run(profile, func(t *testing.T) {
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					matches := map[int]int{}
					waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithRootFS(crs.FS).WithErrorCallback(func(m types.MatchedRule) { matches[m.Rule().ID()] = int(m.Rule().Phase()) }).WithDirectives("Include @coraza.conf-recommended\nSecRuleEngine On\nInclude @crs-setup.conf.example\nInclude @owasp_crs/*.conf\n"))
					if err != nil {
						t.Fatal(err)
					}
					source := &bodyResearchReader{reader: strings.NewReader(tc.body)}
					if tc.fail {
						source.reader = failingReader{}
						if tc.name == "partial-read-error" {
							source.reader = partialFailure{}
						}
					}
					req := httptest.NewRequest("POST", "http://example.test/", nil)
					req.Body = source
					req.ContentLength = tc.length
					if tc.length == -2 {
						req.ContentLength = int64(len(tc.body))
					}
					if req.ContentLength >= 0 {
						req.Header.Set("Content-Length", strconv.FormatInt(req.ContentLength, 10))
					} else {
						req.TransferEncoding = []string{"chunked"}
					}
					req.Header.Set("Content-Type", tc.media)
					req.Header.Set("User-Agent", "Aegvium synthetic research")
					req.Header.Set("Accept", "*/*")
					if tc.encoding != "" {
						req.Header.Set("Content-Encoding", tc.encoding)
					}
					backend := 0
					next := corazahttp.WrapHandler(waf, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						backend++
						data, err := io.ReadAll(r.Body)
						if err != nil || string(data) != tc.body {
							t.Errorf("admitted body changed: %v", err)
						}
						w.WriteHeader(200)
					}))
					if profile == "gated" {
						next = boundedResearchBody(next)
					}
					rr := httptest.NewRecorder()
					next.ServeHTTP(rr, req)
					ids := make([]int, 0, len(matches))
					for id := range matches {
						ids = append(ids, id)
					}
					sort.Ints(ids)
					phases := make([]int, len(ids))
					for i, id := range ids {
						phases[i] = matches[id]
					}
					item := struct {
						Profile string `json:"profile"`
						Case    string `json:"case"`
						Status  int    `json:"status"`
						Backend int    `json:"backend"`
						Read    int    `json:"read"`
						Closed  int    `json:"closed"`
						Rules   []int  `json:"rules"`
						Phases  []int  `json:"phases"`
					}{profile, tc.name, rr.Code, backend, source.bytes, source.closes, ids, phases}
					data, err := json.Marshal(item)
					if err != nil {
						t.Fatal(err)
					}
					t.Logf("BODY-ADMISSION %s", data)
					status, count := tc.baseStatus, tc.baseBackend
					if profile == "gated" {
						status, count = tc.gateStatus, tc.gateBackend
					}
					if rr.Code != status || backend != count {
						t.Fatalf("body result %s; expected %d/%d", data, status, count)
					}
					if profile == "gated" && (source.bytes > bodyResearchCap+1 || source.closes != 1) {
						t.Fatalf("gate read/ownership result %s", data)
					}
					if profile == "baseline" {
						source.Close()
					}
				})
			}
		})
	}
}

func TestBodyAdmissionHeaders(t *testing.T) {
	body := `{"payload":"ordinary"}`
	for _, tc := range []struct {
		name            string
		media, encoding []string
		length          int64
		status          int
	}{
		{"utf8-json", []string{"application/json; charset=UTF-8"}, nil, int64(len(body)), 200},
		{"identity-json", []string{"application/json"}, []string{"identity"}, int64(len(body)), 200},
		{"duplicate-media", []string{"application/json", "text/plain"}, nil, int64(len(body)), 415},
		{"malformed-media", []string{"application/json; broken"}, nil, int64(len(body)), 415},
		{"unsupported-charset", []string{"application/json; charset=utf-16"}, nil, int64(len(body)), 415},
		{"duplicate-encoding", []string{"application/json"}, []string{"identity", "gzip"}, int64(len(body)), 415},
		{"short-declared", []string{"application/json"}, nil, int64(len(body) - 1), 400},
		{"long-declared", []string{"application/json"}, nil, int64(len(body) + 1), 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			original := &bodyResearchReader{reader: strings.NewReader(body)}
			req := httptest.NewRequest("POST", "http://example.test/", nil)
			req.Body = original
			req.ContentLength = tc.length
			req.Header["Content-Type"] = tc.media
			req.Header["Content-Encoding"] = tc.encoding
			calls := 0
			next := boundedResearchBody(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				data, err := io.ReadAll(r.Body)
				if err != nil || string(data) != body {
					t.Errorf("admitted body changed: %v", err)
				}
				w.WriteHeader(200)
			}))
			rr := httptest.NewRecorder()
			next.ServeHTTP(rr, req)
			want := 0
			if tc.status == 200 {
				want = 1
			}
			if rr.Code != tc.status || calls != want || original.closes != 1 || original.bytes > 129 {
				t.Fatalf("header gate status=%d calls=%d closes=%d bytes=%d", rr.Code, calls, original.closes, original.bytes)
			}
			if tc.status == 415 && original.bytes != 0 {
				t.Fatal("unsupported header consumed body")
			}
		})
	}
}
