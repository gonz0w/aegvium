// SPDX-License-Identifier: BSD-3-Clause
package requestctx_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/gonz0w/aegvium/internal/requestctx"
)

func TestPublicAPIHasNoPeerAuthenticationShortcut(t *testing.T) {
	s, err := requestctx.NewSnapshot(strings.Repeat("1", 32), []requestctx.Route{{ID: "app", PublicName: "app.example.test", Port: 443, PolicyPin: strings.Repeat("a", 64), FrontendPeers: []string{"frontend.example.test"}}})
	if err != nil {
		t.Fatal(err)
	}
	dst := &requestctx.Recorder{}
	if err := s.Record(context.Background(), requestctx.Peer{}, requestctx.Request{}, dst); !errors.Is(err, requestctx.ErrPeer) || len(dst.Records()) != 0 {
		t.Fatal("zero peer gained authentication authority")
	}
}
