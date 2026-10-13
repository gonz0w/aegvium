// SPDX-License-Identifier: BSD-3-Clause
package spike

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/fs"
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

//go:embed crs-inputs.json
var corpusRuleManifest []byte

// Small synthetic role/mode comparison, not an upstream CRS regression corpus.
func TestPinnedCRSRequestCorpus(t *testing.T) {
	var manifest struct {
		Bundle string `json:"bundle"`
		Files  []struct {
			Path   string `json:"path"`
			SHA256 string `json:"sha256"`
		} `json:"files"`
	}
	if err := json.Unmarshal(corpusRuleManifest, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Bundle != "github.com/corazawaf/coraza-coreruleset/v4@v4.25.0" || len(manifest.Files) != 51 {
		t.Fatal("unexpected pinned bundle manifest")
	}
	for _, file := range manifest.Files {
		data, err := fs.ReadFile(crs.FS, file.Path)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != file.SHA256 {
			t.Fatalf("pinned rule input changed: %s", file.Path)
		}
	}
	t.Logf("CRS-INPUTS %x", sha256.Sum256(corpusRuleManifest))
	for _, mode := range []string{"On", "DetectionOnly"} {
		t.Run(mode, func(t *testing.T) {
			for _, role := range []string{"query", "form", "json", "cookie"} {
				for _, kind := range []string{"benign", "sql", "script"} {
					t.Run(role+"-"+kind, func(t *testing.T) {
						value := map[string]string{"benign": "ordinary words 123", "sql": "' OR 1=1--", "script": "<script>alert(1)</script>"}[kind]
						matches := map[int]int{}
						waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithRootFS(crs.FS).WithErrorCallback(func(m types.MatchedRule) {
							matches[m.Rule().ID()] = int(m.Rule().Phase())
						}).WithDirectives("Include @coraza.conf-recommended\nSecRuleEngine " + mode + "\nInclude @crs-setup.conf.example\nInclude @owasp_crs/*.conf\n"))
						if err != nil {
							t.Fatal(err)
						}
						target, body, method, content := "http://example.test/", "", "GET", ""
						switch role {
						case "query":
							target += "?" + url.Values{"payload": {value}}.Encode()
						case "form":
							method, content, body = "POST", "application/x-www-form-urlencoded", url.Values{"payload": {value}}.Encode()
						case "json":
							method, content = "POST", "application/json"
							b, err := json.Marshal(map[string]string{"payload": value})
							if err != nil {
								t.Fatal(err)
							}
							body = string(b)
						}
						req := httptest.NewRequest(method, target, strings.NewReader(body))
						req.Header.Set("User-Agent", "Aegvium synthetic research")
						req.Header.Set("Accept", "*/*")
						if content != "" {
							req.Header.Set("Content-Type", content)
							req.Header.Set("Content-Length", strconv.Itoa(len(body)))
						}
						if role == "cookie" {
							req.Header.Set("Cookie", "payload="+value)
						}
						receipts := 0
						rr := httptest.NewRecorder()
						corazahttp.WrapHandler(waf, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
							receipts++
							got, err := io.ReadAll(r.Body)
							if err != nil || string(got) != body {
								t.Errorf("body preservation failed: %v", err)
							}
							if role == "query" && r.URL.Query().Get("payload") != value {
								t.Error("query changed")
							}
							if role == "cookie" && r.Header.Get("Cookie") != "payload="+value {
								t.Error("cookie changed")
							}
							w.WriteHeader(200)
						})).ServeHTTP(rr, req)
						status, count := 200, 1
						if kind != "benign" && mode == "On" {
							status, count = 403, 0
						}
						ids := make([]int, 0, len(matches))
						family := false
						for id := range matches {
							ids = append(ids, id)
							if kind == "sql" && id/1000 == 942 || kind == "script" && id/1000 == 941 {
								family = true
							}
						}
						sort.Ints(ids)
						phases := make([]int, len(ids))
						for i, id := range ids {
							phases[i] = matches[id]
						}
						observation := struct {
							Mode    string `json:"mode"`
							Role    string `json:"role"`
							Kind    string `json:"kind"`
							Status  int    `json:"status"`
							Backend int    `json:"backend"`
							Rules   []int  `json:"rules"`
							Phases  []int  `json:"phases"`
						}{mode, role, kind, rr.Code, receipts, ids, phases}
						data, err := json.Marshal(observation)
						if err != nil {
							t.Fatal(err)
						}
						t.Logf("CRS-CORPUS %s", data)
						if rr.Code != status || receipts != count || kind != "benign" && !family {
							t.Fatalf("unexpected corpus outcome: %s; want status/backend %d/%d and attack family", data, status, count)
						}
					})
				}
			}
		})
	}
}
