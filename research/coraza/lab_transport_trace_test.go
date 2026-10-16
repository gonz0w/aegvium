// SPDX-License-Identifier: BSD-3-Clause
package spike

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// Fixture-only metadata. No Error(), request or certificate data enters a row.
type labTransportTrace struct {
	origin time.Time
	next   atomic.Int64
}
type labTransportCall struct {
	owner   *labTransportTrace
	id      int64
	name    string
	started time.Time
	done    atomic.Bool
}
type labTransportRow struct {
	ID            int64  `json:"id"`
	Case          string `json:"case"`
	StartMS       int64  `json:"start_ms"`
	DurationMS    int64  `json:"duration_ms"`
	Status        int    `json:"status"`
	Stage         string `json:"stage"`
	Class         string `json:"class"`
	HealthSamples int32  `json:"health_samples"`
	HealthAgeMS   int64  `json:"health_age_ms"`
}

var labTraceLabel = regexp.MustCompile(`^[a-z][a-z0-9-]{0,47}$`)
var errLabTraceBodyLimit = errors.New("fixture response bound")

func labTransportClass(err error) string {
	if err == nil {
		return "none"
	}
	switch {
	case errors.Is(err, errLabTraceBodyLimit):
		return "body-limit"
	case errors.Is(err, context.Canceled):
		return "cancelled"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "refused"
	case errors.Is(err, syscall.ECONNRESET):
		return "reset"
	case errors.Is(err, syscall.EPIPE):
		return "broken-pipe"
	case errors.Is(err, syscall.EHOSTUNREACH):
		return "unreachable"
	case errors.Is(err, io.ErrUnexpectedEOF):
		return "unexpected-eof"
	case errors.Is(err, io.EOF):
		return "eof"
	case errors.Is(err, net.ErrClosed):
		return "closed"
	}
	var unknown x509.UnknownAuthorityError
	var name x509.HostnameError
	var invalid x509.CertificateInvalidError
	if errors.As(err, &unknown) || errors.As(err, &name) || errors.As(err, &invalid) {
		return "tls-certificate"
	}
	var record tls.RecordHeaderError
	var alert tls.AlertError
	if errors.As(err, &record) || errors.As(err, &alert) {
		return "tls-protocol"
	}
	var dns *net.DNSError
	if errors.As(err, &dns) {
		return "dns"
	}
	if labTraceTimeoutIn(err, 0) {
		return "timeout"
	}
	return "other"
}

// Some wrappers implement net.Error but return false from Timeout even when a
// deeper wrapped error times out. Walk wrappers without formatting their data.
func labTraceTimeoutIn(err error, depth int) bool {
	if err == nil || depth > 16 {
		return false
	}
	if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		return true
	}
	switch wrapped := err.(type) {
	case interface{ Unwrap() error }:
		return labTraceTimeoutIn(wrapped.Unwrap(), depth+1)
	case interface{ Unwrap() []error }:
		for _, cause := range wrapped.Unwrap() {
			if labTraceTimeoutIn(cause, depth+1) {
				return true
			}
		}
	}
	return false
}
func newLabTransportTrace() *labTransportTrace { return &labTransportTrace{origin: time.Now()} }
func (o *labTransportTrace) elapsedMS() int64  { return time.Since(o.origin).Milliseconds() }
func (o *labTransportTrace) begin(name string) (*labTransportCall, error) {
	if !labTraceLabel.MatchString(name) {
		return nil, errors.New("fixture diagnostic label invalid")
	}
	return &labTransportCall{owner: o, id: o.next.Add(1), name: name, started: time.Now()}, nil
}
func (call *labTransportCall) finish(stage string, status int, err error, samples int32, lastMS int64) (labTransportRow, error) {
	class := labTransportClass(err)
	finished := time.Now()
	endMS := finished.Sub(call.owner.origin).Milliseconds()
	if (stage != "roundtrip" && stage != "body" && stage != "complete") || (stage == "roundtrip" && (status != 0 || err == nil)) || (stage == "complete" && err != nil) || (stage == "body" && err == nil) || (stage != "roundtrip" && (status < 100 || status > 599)) || samples < 0 || (samples > 0 && (lastMS < 0 || lastMS > endMS)) {
		return labTransportRow{}, errors.New("fixture diagnostic completion invalid")
	}
	if !call.done.CompareAndSwap(false, true) {
		return labTransportRow{}, errors.New("fixture diagnostic repeated")
	}
	row := labTransportRow{ID: call.id, Case: call.name, StartMS: call.started.Sub(call.owner.origin).Milliseconds(), DurationMS: finished.Sub(call.started).Milliseconds(), Status: status, Stage: stage, Class: class, HealthSamples: samples, HealthAgeMS: -1}
	if samples > 0 {
		row.HealthAgeMS = endMS - lastMS
	}
	return row, nil
}

type labTraceTimeout struct{}

func (labTraceTimeout) Error() string   { return "sensitive-diagnostic-marker" }
func (labTraceTimeout) Timeout() bool   { return true }
func (labTraceTimeout) Temporary() bool { return true }

func TestLabTransportTraceClasses(t *testing.T) {
	cases := []struct {
		name  string
		err   error
		class string
	}{
		{"success", nil, "none"}, {"cancel", context.Canceled, "cancelled"}, {"deadline", context.DeadlineExceeded, "deadline"},
		{"refused", syscall.ECONNREFUSED, "refused"}, {"reset", syscall.ECONNRESET, "reset"}, {"pipe", syscall.EPIPE, "broken-pipe"}, {"unreachable", syscall.EHOSTUNREACH, "unreachable"},
		{"eof", io.EOF, "eof"}, {"partial", io.ErrUnexpectedEOF, "unexpected-eof"}, {"closed", net.ErrClosed, "closed"},
		{"authority", x509.UnknownAuthorityError{Cert: &x509.Certificate{}}, "tls-certificate"}, {"hostname", x509.HostnameError{Certificate: &x509.Certificate{}, Host: "fixture.invalid"}, "tls-certificate"}, {"certificate", x509.CertificateInvalidError{Cert: &x509.Certificate{}, Reason: x509.Expired}, "tls-certificate"},
		{"record", tls.RecordHeaderError{}, "tls-protocol"}, {"alert", tls.AlertError(42), "tls-protocol"}, {"dns", &net.DNSError{Name: "private.invalid"}, "dns"},
		{"timeout", &net.DNSError{IsTimeout: true}, "dns"}, {"net-timeout", labTraceTimeout{}, "timeout"}, {"joined-timeout", errors.Join(errors.New("private"), labTraceTimeout{}), "timeout"}, {"limit", errLabTraceBodyLimit, "body-limit"}, {"opaque", errors.New("sensitive-diagnostic-marker"), "other"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if labTransportClass(tc.err) != tc.class {
				t.Fatal("class mismatch")
			}
			if tc.err != nil {
				wrapped := &url.Error{Op: "private", URL: "http://private.invalid/hidden", Err: fmt.Errorf("sensitive-diagnostic-marker: %w", tc.err)}
				if labTransportClass(wrapped) != tc.class {
					t.Fatal("nested class mismatch")
				}
			}
		})
	}
}
func TestLabTransportTraceLifecycle(t *testing.T) {
	owner := newLabTransportTrace()
	for _, name := range []string{"", "bad label", "http://private.invalid", "private\nvalue", strings.Repeat("x", 49)} {
		if _, err := owner.begin(name); err == nil {
			t.Fatal("invalid label")
		}
	}
	call, err := owner.begin("reload-get")
	if err != nil {
		t.Fatal("begin failed")
	}
	for _, stage := range []string{"", "private-value"} {
		if _, err := call.finish(stage, 200, nil, 0, 0); err == nil {
			t.Fatal("invalid stage")
		}
	}
	if _, err := call.finish("complete", 0, nil, 0, 0); err == nil {
		t.Fatal("invalid status")
	}
	if _, err := call.finish("body", 200, nil, 0, 0); err == nil {
		t.Fatal("missing body error")
	}
	if _, err := call.finish("complete", 200, nil, 1, owner.elapsedMS()+1000); err == nil {
		t.Fatal("future health")
	}
	row, err := call.finish("roundtrip", 0, errors.New("sensitive-diagnostic-marker"), 0, 0)
	if err != nil {
		t.Fatal("finish failed")
	}
	raw, _ := json.Marshal(row)
	if strings.Contains(string(raw), "sensitive-diagnostic-marker") || row.Class != "other" || row.ID != 1 || row.StartMS < 0 || row.DurationMS < 0 || row.HealthAgeMS != -1 {
		t.Fatal("diagnostic redaction/lifecycle")
	}
	if _, err := call.finish("roundtrip", 0, io.EOF, 0, 0); err == nil {
		t.Fatal("double completion")
	}
	var wg sync.WaitGroup
	ids := make(chan int64, 32)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, e := owner.begin("benign-get")
			if e != nil {
				t.Error("begin")
				return
			}
			r, e := c.finish("complete", 200, nil, 1, 0)
			if e != nil {
				t.Error("finish")
				return
			}
			ids <- r.ID
		}()
	}
	wg.Wait()
	close(ids)
	seen := map[int64]bool{}
	for id := range ids {
		if seen[id] || id < 2 || id > 33 {
			t.Fatal("call ID drift")
		}
		seen[id] = true
	}
	if len(seen) != 32 {
		t.Fatal("lost calls")
	}
}

type labTraceTransport func(*http.Request) (*http.Response, error)

func (f labTraceTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestLabTransportTraceFakeClient(t *testing.T) {
	// No listener, DNS resolution, network call or security fixture executes.
	trace := newLabTransportTrace()
	client := &http.Client{Transport: labTraceTransport(func(*http.Request) (*http.Response, error) { return nil, syscall.ECONNRESET })}
	request, _ := http.NewRequest("GET", "http://fixture.invalid/benign", nil)
	call, _ := trace.begin("benign-get")
	_, err := client.Do(request)
	row, e := call.finish("roundtrip", 0, err, 0, 0)
	if e != nil || row.Class != "reset" || row.Status != 0 || row.Stage != "roundtrip" {
		t.Fatal("client outcome classification")
	}
	raw, _ := json.Marshal(row)
	if strings.Contains(string(raw), "fixture.invalid") || strings.Contains(string(raw), "benign/") {
		t.Fatal("request data leaked")
	}
}
