//go:build aegvium_binding_compile

// SPDX-License-Identifier: BSD-3-Clause
package bodyowner

// Compile only. Never execute this tagged test binary: default orchestration
// tests import API-only packages and use synthetic transactions exclusively.
import (
	"io"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/experimental"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

var _ transactionFactory = coraza.WAF(nil)
var _ transactionState = plugintypes.TransactionState(nil)
var _ io.Closer = experimental.WAFCloser(nil)
