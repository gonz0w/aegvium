// SPDX-License-Identifier: BSD-3-Clause
package spike

import "net/http"

const LabRequestLimit = 4

// One owner spans route generations. No waiting queue or unchecked overflow path.
func labAdmission(next http.Handler) http.Handler {
	slots := make(chan struct{}, LabRequestLimit)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			w.Header().Set("Connection", "close")
			http.Error(w, "inspection busy", 503)
			return
		}
		next.ServeHTTP(w, r)
	})
}
