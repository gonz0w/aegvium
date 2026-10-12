// SPDX-License-Identifier: BSD-3-Clause
package spike

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3"
	corazahttp "github.com/corazawaf/coraza/v3/http"
	"github.com/corazawaf/coraza/v3/types"
)

const rules = `
SecRuleEngine On
SecRequestBodyAccess On
SecRequestBodyLimit 64
SecRequestBodyLimitAction Reject
SecRule REQUEST_URI "@contains forbidden" "id:1001,phase:1,log,deny,status:403"
SecRule ARGS:payload "@streq forbidden" "id:1002,phase:2,log,deny,status:403"
`

// The upstream HTTP middleware measures interruption before a synthetic backend.
// It is not an HTTP proxy and is never installed as a service.
func TestRequestInterruption(t *testing.T) {
	for _, tc := range []struct {
		name, engine, uri, body string
		status, backend         int
	}{
		{"benign-get", "On", "/allowed", "", 200, 1},
		{"uri-denied", "On", "/forbidden", "", 403, 0},
		{"benign-post", "On", "/allowed", "payload=ordinary", 200, 1},
		{"body-denied", "On", "/allowed", "payload=forbidden", 403, 0},
		{"body-limit", "On", "/allowed", "payload=" + strings.Repeat("x", 100), 413, 0},
		{"detection-uri", "DetectionOnly", "/forbidden", "", 200, 1},
		{"detection-body", "DetectionOnly", "/allowed", "payload=forbidden", 200, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			matches := 0
			waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithErrorCallback(func(types.MatchedRule) { matches++ }).WithDirectives(strings.Replace(rules, "SecRuleEngine On", "SecRuleEngine "+tc.engine, 1)))
			if err != nil {
				t.Fatal(err)
			}
			method := "GET"
			if tc.body != "" {
				method = "POST"
			}
			req := httptest.NewRequest(method, "http://example.test"+tc.uri, strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			receipts := 0
			rr := httptest.NewRecorder()
			backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				receipts++
				got, err := io.ReadAll(r.Body)
				if err != nil || string(got) != tc.body {
					t.Errorf("backend body=%q err=%v; want %q", got, err, tc.body)
				}
				w.WriteHeader(http.StatusOK)
			})
			corazahttp.WrapHandler(waf, backend).ServeHTTP(rr, req)

			if rr.Code != tc.status || receipts != tc.backend {
				t.Fatalf("status=%d backend=%d; want status=%d backend=%d", rr.Code, receipts, tc.status, tc.backend)
			}
			if strings.HasPrefix(tc.name, "detection-") && matches == 0 {
				t.Fatal("DetectionOnly forwarded without recorded match")
			}
		})
	}
}

func TestInvalidRulesRejected(t *testing.T) {
	_, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives("SecRuleEngine Impossible"))
	if err == nil {
		t.Fatal("invalid rule configuration was accepted")
	}
}

// Characterize the upstream error response, rather than treating HTTP success as
// proof that inspection succeeded. This observation is an adoption constraint.
func TestBodyReadFailure(t *testing.T) {
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(rules))
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "http://example.test/allowed", nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Body = io.NopCloser(failingReader{})
	receipts := 0
	rr := httptest.NewRecorder()
	corazahttp.WrapHandler(waf, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { receipts++ })).ServeHTTP(rr, req)
	if receipts != 0 {
		t.Fatalf("read error reached backend %d times", receipts)
	}
	// v3.8.1 returns without writing an error status; net/http therefore defaults
	// to 200. A production integration must specify explicit failure responses.
	if rr.Code != http.StatusOK {
		t.Fatalf("upstream error status changed: got %d; review this characterization", rr.Code)
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

// explicitFailure is a test-only completion experiment, not a proxy API.
// Silence before backend admission must never look like a successful response.
func explicitFailure(waf coraza.WAF, backend http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded := false
		response := &completionWriter{ResponseWriter: w}
		corazahttp.WrapHandler(waf, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			forwarded = true
			backend.ServeHTTP(w, r)
		})).ServeHTTP(response, r)
		if !forwarded && !response.final {
			http.Error(response, "inspection incomplete", http.StatusInternalServerError)
		}
	})
}

type completionWriter struct {
	http.ResponseWriter
	final bool
}

func (w *completionWriter) WriteHeader(status int) {
	if status >= 200 {
		w.final = true
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *completionWriter) Write(body []byte) (int, error) {
	w.final = true
	return w.ResponseWriter.Write(body)
}

type partialFailure struct{}

func (partialFailure) Read(p []byte) (int, error) {
	return copy(p, "payload=ordinary"), io.ErrUnexpectedEOF
}

func TestExplicitInspectionError(t *testing.T) {
	for _, tc := range []struct {
		name, engine, uri, body string
		reader                  io.Reader
		status, backend         int
	}{
		{"empty-benign", "On", "/allowed", "", nil, 200, 1},
		{"benign-post", "On", "/allowed", "payload=ordinary", nil, 200, 1},
		{"read-error", "On", "/allowed", "", failingReader{}, 500, 0},
		{"partial-read-error", "On", "/allowed", "", partialFailure{}, 500, 0},
		{"uri-denied", "On", "/forbidden", "", nil, 403, 0},
		{"body-denied", "On", "/allowed", "payload=forbidden", nil, 403, 0},
		{"detection-uri", "DetectionOnly", "/forbidden", "", nil, 200, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			matches := 0
			waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithErrorCallback(func(types.MatchedRule) { matches++ }).WithDirectives(strings.Replace(rules, "SecRuleEngine On", "SecRuleEngine "+tc.engine, 1)))
			if err != nil {
				t.Fatal(err)
			}
			method := "GET"
			if tc.body != "" || tc.reader != nil {
				method = "POST"
			}
			req := httptest.NewRequest(method, "http://example.test"+tc.uri, strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if tc.reader != nil {
				req.Body = io.NopCloser(tc.reader)
				req.ContentLength = -1
			}
			receipts := 0
			rr := httptest.NewRecorder()
			explicitFailure(waf, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				receipts++
				body, err := io.ReadAll(r.Body)
				if err != nil || string(body) != tc.body {
					t.Errorf("backend body=%q err=%v; want %q", body, err, tc.body)
				}
				// Leave the backend's valid implicit-200 behavior intact.
			})).ServeHTTP(rr, req)
			if rr.Code != tc.status || receipts != tc.backend {
				t.Fatalf("status=%d backend=%d; want status=%d backend=%d", rr.Code, receipts, tc.status, tc.backend)
			}
			if tc.status == 500 && rr.Body.String() != "inspection incomplete\n" {
				t.Fatalf("unexpected error response %q", rr.Body.String())
			}
			if tc.engine == "DetectionOnly" && matches == 0 {
				t.Fatal("DetectionOnly forwarded without recorded match")
			}
		})
	}
}
