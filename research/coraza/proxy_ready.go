// SPDX-License-Identifier: BSD-3-Clause
package spike

import (
	"io"
	"net/http"
	"time"
)

// Dedicated research health role: no application handler or routing fallback.
// Receiver readiness still uses a synthetic engine flag, not loaded-rule proof.
func proxyReadyHandler(receiver *proxyV1Listener) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		code, body := http.StatusNotFound, "not found\n"
		if r.URL.Path == "/ready" && r.URL.RawQuery == "" && !r.URL.ForceQuery {
			switch r.Method {
			case http.MethodGet, http.MethodHead:
				code, body = http.StatusServiceUnavailable, "unavailable\n"
				if receiver != nil && receiver.Ready() {
					code, body = http.StatusOK, "ready\n"
				}
			default:
				code, body = http.StatusMethodNotAllowed, "method not allowed\n"
				w.Header().Set("Allow", "GET, HEAD")
			}
		}
		w.WriteHeader(code)
		if r.Method != http.MethodHead {
			_, _ = io.WriteString(w, body)
		}
	})
}

// Fixture profile only; deployment exposure and resource budgets are unqualified.
func proxyReadyServer(receiver *proxyV1Listener) *http.Server {
	return &http.Server{Handler: proxyReadyHandler(receiver), ReadHeaderTimeout: time.Second,
		ReadTimeout: 2 * time.Second, WriteTimeout: 2 * time.Second, IdleTimeout: time.Second,
		MaxHeaderBytes: 4096}
}
