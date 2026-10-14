// SPDX-License-Identifier: BSD-3-Clause
package comparison

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	_ "github.com/corazawaf/coraza-caddy/v2"
	crs "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
	corazahttp "github.com/corazawaf/coraza/v3/http"
)

// Caddy's registered module, provisioning and cleanup are real. The outer
// net/http error renderer and transport are fixture code, not Caddy's server.
func prepare(profile, rules string, embedded bool, next http.Handler) (http.Handler, func(), error) {
	if profile == "engine" {
		config := coraza.NewWAFConfig().WithDirectives(rules)
		if embedded {
			config = config.WithRootFS(crs.FS)
		}
		waf, e := coraza.NewWAF(config)
		if e != nil {
			return nil, nil, e
		}
		return corazahttp.WrapHandler(waf, next), func() { _ = waf.(io.Closer).Close() }, nil
	}
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	raw, _ := json.Marshal(map[string]any{"directives": rules, "load_owasp_crs": embedded})
	mod, e := ctx.LoadModuleByID("http.handlers.waf", raw)
	if e != nil {
		cancel()
		return nil, nil, e
	}
	handler := mod.(caddyhttp.MiddlewareHandler)
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = caddyhttp.PrepareRequest(r, caddy.NewReplacer(), w, &caddyhttp.Server{})
		e := handler.ServeHTTP(w, r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error { next.ServeHTTP(w, r); return nil }))
		if e != nil {
			code := 500
			var he caddyhttp.HandlerError
			if errors.As(e, &he) {
				code = he.StatusCode
			}
			http.Error(w, "inspection rejected", code)
		}
	})
	return h, cancel, nil
}
