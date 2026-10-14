// SPDX-License-Identifier: BSD-3-Clause
package spike

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestLabAdmissionConcurrent(t *testing.T) {
	entered := make(chan struct{}, 4)
	release := make(chan struct{})
	var effects atomic.Int32
	handler := labAdmission(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		effects.Add(1)
		if r.URL.Path == "/held" {
			entered <- struct{}{}
			<-release
		}
		w.WriteHeader(200)
	}))
	var done sync.WaitGroup
	for i := 0; i < LabRequestLimit; i++ {
		done.Add(1)
		go func() {
			defer done.Done()
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, httptest.NewRequest("GET", "/held", nil))
			if w.Code != 200 {
				t.Error("admitted request changed")
			}
		}()
	}
	for i := 0; i < LabRequestLimit; i++ {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("held request deadline")
		}
	}
	overflow := httptest.NewRecorder()
	handler.ServeHTTP(overflow, httptest.NewRequest("GET", "/overflow", nil))
	if overflow.Code != 503 || overflow.Body.String() != "inspection busy\n" || effects.Load() != 4 {
		t.Fatal("saturation forwarded or response changed")
	}
	close(release)
	done.Wait()
	recovery := httptest.NewRecorder()
	handler.ServeHTTP(recovery, httptest.NewRequest("GET", "/recovery", nil))
	if recovery.Code != 200 || effects.Load() != 5 {
		t.Fatal("slots did not recover")
	}
}
func TestLabAdmissionReleasesAfterPanic(t *testing.T) {
	handler := labAdmission(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/panic" {
			panic("controlled handler failure")
		}
		w.WriteHeader(403)
	}))
	for i := 0; i < LabRequestLimit+1; i++ {
		func() {
			defer func() {
				if recover() == nil {
					t.Error("panic did not reach server boundary")
				}
			}()
			handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/panic", nil))
		}()
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", "/deny", nil))
	if w.Code != 403 {
		t.Fatal("failed handler leaked admission slot")
	}
}
