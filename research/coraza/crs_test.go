// SPDX-License-Identifier: BSD-3-Clause
package spike

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	crs "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
	corazahttp "github.com/corazawaf/coraza/v3/http"
	"github.com/corazawaf/coraza/v3/types"
)

// This is a bounded smoke set, not the CRS regression corpus or OWASP coverage.
func TestPinnedCRSSmoke(t *testing.T) {
	for _, tc := range []struct {
		name, query, body string
		status, backend   int
	}{
		{"benign-query", "ordinary", "", 200, 1},
		{"benign-post", "ordinary", "payload=ordinary", 200, 1},
		{"sql-injection", "' OR 1=1--", "", 403, 0},
		{"script-injection", "<script>alert(1)</script>", "", 403, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			matches := 0
			waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithRootFS(crs.FS).WithErrorCallback(func(types.MatchedRule) { matches++ }).WithDirectives(`
Include @coraza.conf-recommended
SecRuleEngine On
Include @crs-setup.conf.example
Include @owasp_crs/*.conf
`))
			if err != nil {
				t.Fatal(err)
			}
			method := "GET"
			if tc.body != "" {
				method = "POST"
			}
			req := httptest.NewRequest(method, "http://example.test/?"+url.Values{"q": {tc.query}}.Encode(), strings.NewReader(tc.body))
			req.Header.Set("User-Agent", "Aegvium synthetic research")
			req.Header.Set("Accept", "*/*")
			if tc.body != "" {
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				req.Header.Set("Content-Length", strconv.Itoa(len(tc.body)))
			}
			receipts := 0
			rr := httptest.NewRecorder()
			backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				receipts++
				body, err := io.ReadAll(r.Body)
				if err != nil || string(body) != tc.body {
					t.Errorf("body not preserved: %q %v", body, err)
				}
				w.WriteHeader(http.StatusOK)
			})
			corazahttp.WrapHandler(waf, backend).ServeHTTP(rr, req)
			if rr.Code != tc.status || receipts != tc.backend {
				t.Fatalf("status=%d backend=%d matches=%d; want %d/%d", rr.Code, receipts, matches, tc.status, tc.backend)
			}
			if tc.backend == 0 && matches == 0 {
				t.Fatal("blocked without CRS match evidence")
			}
		})
	}
}
