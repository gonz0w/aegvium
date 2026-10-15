// SPDX-License-Identifier: BSD-3-Clause
package spike

import (
	"bytes"
	"errors"
	"io"
	"net/http"
)

// Coraza owns its body reader until the inspection handler returns. The backend
// transport may keep reading after RoundTrip returns, so it must own other bytes.
type labBodyTransport struct{ base http.RoundTripper }

func (t labBodyTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	copy := request.Clone(request.Context())
	copy.GetBody = nil
	if request.Body != nil && request.Body != http.NoBody {
		data, readErr := io.ReadAll(io.LimitReader(request.Body, LabBodyLimit+1))
		closeErr := request.Body.Close()
		if readErr != nil || closeErr != nil || len(data) > LabBodyLimit || (request.ContentLength >= 0 && request.ContentLength != int64(len(data))) {
			return nil, errors.New("lab inspected body unavailable")
		}
		copy.Body = io.NopCloser(bytes.NewReader(data))
	}
	return t.base.RoundTrip(copy)
}
