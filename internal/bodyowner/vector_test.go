// SPDX-License-Identifier: BSD-3-Clause
package bodyowner_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gonz0w/aegvium/internal/bodyowner"
)

type segment struct {
	DataASCII string `json:"data_ascii"`
	ByteASCII string `json:"byte_ascii"`
	ByteCount int    `json:"byte_count"`
}

func (s segment) bytes() []byte {
	return []byte(s.DataASCII + strings.Repeat(s.ByteASCII, s.ByteCount))
}

type readRow struct {
	segment
	Repeat    int    `json:"repeat"`
	ReportedN *int   `json:"reported_n"`
	Error     string `json:"error"`
}

type bodyVector struct {
	ID       string    `json:"id"`
	Declared int       `json:"declared_length"`
	Reads    []readRow `json:"reads"`
	CloseErr bool      `json:"close_error"`
	Expected struct {
		ReadCalls int `json:"read_calls"`
		Sizes     []struct {
			Size, Repeat int
		} `json:"requested_buffer_sizes"`
		CloseCalls int `json:"close_calls"`
		Outcome    struct {
			Joined, Recorded, Canceled, Retired, Stopped, CloseFailed bool
			ReadFailure                                               bodyowner.Failure
			Record                                                    struct {
				Generation string
				Body       []segment
			}
		}
		Usage        struct{ Requests, Sockets int }
		InboundError string `json:"inbound_close_error"`
		FutureError  string `json:"owner_future_reserve_error"`
	} `json:"expected"`
}

type scriptedBody struct {
	rows       []readRow
	sizes      []int
	closeCalls int
	closeError bool
	unexpected bool
}

func (s *scriptedBody) Read(p []byte) (int, error) {
	s.sizes = append(s.sizes, len(p))
	if len(s.rows) == 0 {
		s.unexpected = true
		return 0, errors.New("unexpected synthetic read")
	}
	row := s.rows[0]
	s.rows = s.rows[1:]
	data := row.bytes()
	copy(p, data)
	n := len(data)
	if row.ReportedN != nil {
		n = *row.ReportedN
	}
	var err error
	switch row.Error {
	case "None":
	case "EOF":
		err = io.EOF
	case "ReadError":
		err = errors.New("synthetic read failure")
	case "ContextCanceled":
		err = context.Canceled
	case "WrappedEOF":
		err = fmt.Errorf("synthetic wrapper: %w", io.EOF)
	default:
		s.unexpected = true
		err = errors.New("unknown synthetic error class")
	}
	return n, err
}

func (s *scriptedBody) Close() error {
	s.closeCalls++
	if s.closeError {
		return errors.New("synthetic close failure")
	}
	return nil
}

func vectorError(err error) string {
	switch err {
	case nil:
		return "None"
	case bodyowner.ErrStopped:
		return "ErrStopped"
	case bodyowner.ErrTransferred:
		return "ErrTransferred"
	default:
		return "unexpected"
	}
}

func TestIndependentReadVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/independent.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Setup   struct{ Generation string }
		Vectors []bodyVector
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Vectors) != 36 {
		t.Fatal("independent fixture count changed")
	}
	totalReads := 0
	for _, v := range fixture.Vectors {
		totalReads += v.Expected.ReadCalls
		t.Run(v.ID, func(t *testing.T) {
			o := bodyowner.New()
			gen, err := o.NewGeneration(fixture.Setup.Generation)
			if err != nil {
				t.Fatal(err)
			}
			in, err := o.ReserveInbound()
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = in.Close() }()
			source := &scriptedBody{closeError: v.CloseErr}
			for _, row := range v.Reads {
				for range row.Repeat {
					source.rows = append(source.rows, row)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			job, err := gen.Begin(ctx, in, source, v.Declared)
			if err != nil {
				t.Fatal(err)
			}
			observer, stop := context.WithTimeout(context.Background(), 3*time.Second)
			defer stop()
			out, err := job.Wait(observer)
			if err != nil {
				t.Fatal(err)
			}
			var wantBody []byte
			for _, s := range v.Expected.Outcome.Record.Body {
				wantBody = append(wantBody, s.bytes()...)
			}
			e := v.Expected.Outcome
			want := bodyowner.Outcome{Joined: e.Joined, Recorded: e.Recorded, Canceled: e.Canceled, Retired: e.Retired, Stopped: e.Stopped, CloseFailed: e.CloseFailed, ReadFailure: e.ReadFailure, Record: bodyowner.Record{Generation: e.Record.Generation, Body: wantBody}}
			if !reflect.DeepEqual(out, want) {
				t.Fatalf("outcome flags/record differ: failure=%s joined=%t recorded=%t canceled=%t retired=%t stopped=%t closefailed=%t bytes=%d", out.ReadFailure, out.Joined, out.Recorded, out.Canceled, out.Retired, out.Stopped, out.CloseFailed, len(out.Record.Body))
			}
			var wantSizes []int
			for _, run := range v.Expected.Sizes {
				for range run.Repeat {
					wantSizes = append(wantSizes, run.Size)
				}
			}
			if source.unexpected || len(source.sizes) != v.Expected.ReadCalls || !reflect.DeepEqual(source.sizes, wantSizes) || source.closeCalls != v.Expected.CloseCalls {
				t.Fatalf("I/O calls differ: reads=%d close=%d", len(source.sizes), source.closeCalls)
			}
			usage := o.Usage()
			if usage.Requests != v.Expected.Usage.Requests || usage.Sockets != v.Expected.Usage.Sockets {
				t.Fatalf("usage differs: %+v", usage)
			}
			if vectorError(in.Close()) != v.Expected.InboundError {
				t.Fatal("post-completion inbound ownership differs")
			}
			fresh, err := o.ReserveInbound()
			if vectorError(err) != v.Expected.FutureError {
				t.Fatal("future owner admission differs")
			}
			if fresh != nil {
				if err := fresh.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if len(out.Record.Body) > 0 {
				out.Record.Body[0] ^= 0xff
			}
			if !bytes.Equal(job.Outcome().Record.Body, wantBody) {
				t.Fatal("returned body aliases private recording")
			}
		})
	}
	if totalReads != 840 {
		t.Fatal("literal expected read count changed")
	}
}
