// SPDX-License-Identifier: BSD-3-Clause
package spike

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type labTransportFunc func(*http.Request) (*http.Response, error)

func (f labTransportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type labTransportSource struct {
	io.Reader
	closes   int
	closeErr error
}

func (s *labTransportSource) Close() error { s.closes++; return s.closeErr }

type labTransportReadError struct{}

func (labTransportReadError) Read([]byte) (int, error) { return 0, errors.New("owned read failure") }

func TestLabBodyTransport(t *testing.T) {
	t.Run("writer-after-transaction-close", func(t *testing.T) {
		// Model a response returning before the transport writer consumes the body.
		// Resetting this source models Coraza's transaction cleanup deterministically.
		sourceBuffer := bytes.NewBufferString("owned body")
		source := &labTransportSource{Reader: sourceBuffer}
		request := httptest.NewRequest("POST", "http://app.test/", source)
		request.ContentLength = -1
		request.TransferEncoding = []string{"chunked"}
		request.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(sourceBuffer), nil }
		request.Header.Set("X-Owned", "before")
		var pending *http.Request
		tr := labBodyTransport{base: labTransportFunc(func(r *http.Request) (*http.Response, error) {
			pending = r
			if source.closes != 1 {
				t.Fatal("body not closed before delegation")
			}
			return &http.Response{StatusCode: 200, Body: http.NoBody}, nil
		})}
		response, e := tr.RoundTrip(request)
		if e != nil {
			t.Fatal(e)
		}
		response.Body.Close()
		sourceBuffer.Reset()
		request.Header.Set("X-Owned", "after")
		data, e := io.ReadAll(pending.Body)
		pending.Body.Close()
		if e != nil || string(data) != "owned body" || pending == request || pending.GetBody != nil || request.GetBody == nil || pending.Header.Get("X-Owned") != "before" || pending.ContentLength != -1 || len(pending.TransferEncoding) != 1 || pending.TransferEncoding[0] != "chunked" || source.closes != 1 {
			t.Fatal("body lifetime or metadata escaped")
		}
	})
	for _, name := range []string{"read", "close", "oversize", "length"} {
		t.Run(name, func(t *testing.T) {
			var reader io.Reader = strings.NewReader("body")
			if name == "read" {
				reader = labTransportReadError{}
			}
			if name == "oversize" {
				reader = strings.NewReader(strings.Repeat("x", LabBodyLimit+1))
			}
			source := &labTransportSource{Reader: reader}
			if name == "close" {
				source.closeErr = errors.New("owned close failure")
			}
			request := httptest.NewRequest("POST", "http://app.test/", source)
			request.ContentLength = 4
			if name == "length" {
				request.ContentLength = 5
			}
			called := false
			tr := labBodyTransport{base: labTransportFunc(func(*http.Request) (*http.Response, error) { called = true; return nil, nil })}
			if _, e := tr.RoundTrip(request); e == nil || called || source.closes != 1 {
				t.Fatal("body fault reached backend or leaked source")
			}
		})
	}
}

type labCancelEOF struct {
	context.Context
	entered chan struct{}
}

func (r labCancelEOF) Read([]byte) (int, error) { close(r.entered); <-r.Done(); return 0, io.EOF }

type labExpiredContext struct{ context.Context }

func (labExpiredContext) Deadline() (time.Time, bool) { return time.Now().Add(-time.Second), true }

func TestLabBufferedResponse(t *testing.T) {
	for _, name := range []string{"healthy", "cancelled-eof", "expired-unnotified", "missing-request", "read-error", "oversize"} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var reader io.Reader = strings.NewReader("owned response")
			var entered chan struct{}
			if name == "cancelled-eof" {
				entered = make(chan struct{})
				reader = labCancelEOF{Context: ctx, entered: entered}
			}
			if name == "read-error" {
				reader = labTransportReadError{}
			}
			if name == "oversize" {
				reader = strings.NewReader(strings.Repeat("x", LabBodyLimit+1))
			}
			if name == "expired-unnotified" {
				ctx = labExpiredContext{Context: ctx}
			}
			source := &labTransportSource{Reader: reader}
			request := httptest.NewRequest("GET", "http://app.test/", nil).WithContext(ctx)
			if name == "missing-request" {
				request = nil
			}
			response := &http.Response{StatusCode: 200, Request: request, Body: source}
			done := make(chan error, 1)
			go func() { done <- labBufferedResponse(response) }()
			if entered != nil {
				<-entered
				cancel()
			}
			err := <-done
			if (err == nil) != (name == "healthy") || source.closes != 1 {
				t.Fatal("response boundary accepted expired/error data", name, err)
			}
			if name == "healthy" {
				data, err := io.ReadAll(response.Body)
				response.Body.Close()
				if err != nil || string(data) != "owned response" {
					t.Fatal("response bytes changed")
				}
			}
		})
	}
}
