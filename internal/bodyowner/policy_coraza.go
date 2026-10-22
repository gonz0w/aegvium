//go:build aegvium_engine_source && no_fs_access

// SPDX-License-Identifier: BSD-3-Clause
package bodyowner

// Source implementation compiled only until separately authorized qualification.
// No init/entrypoint calls it. No actual constructor runs in portable fixtures.
import (
	"io"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/debuglog"
	"github.com/corazawaf/coraza/v3/experimental"
	"github.com/corazawaf/coraza/v3/experimental/plugins"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/types"
)

var pinnedPolicyStartup = newPolicyStartup()

func newPinnedEngineOwner() (*Owner, error) {
	return pinnedPolicyStartup.construct(func() (policyConstruction, error) {
		plugins.RegisterAuditLogWriter(policyWriterName, func() plugintypes.AuditLogWriter { return noOutputAuditWriter{} })
		waf, err := coraza.NewWAF(coraza.NewWAFConfig().
			WithRootFS(coreruleset.FS).
			WithDirectives(policyDirectives).
			WithRequestBodyAccess().
			WithRequestBodyLimit(MaxBody + 1).
			WithRequestBodyInMemoryLimit(MaxBody + 1).
			WithDebugLogger(debuglog.Noop()).
			WithErrorCallback(func(types.MatchedRule) {}))
		result := policyConstruction{factory: waf}
		if closer, ok := waf.(io.Closer); ok {
			result.closer = closer
		}
		pinnedPolicyStartup.hold(result)
		if err != nil || waf == nil {
			return result, errPolicyPreparation
		}
		counter, ok := waf.(experimental.WAFWithRules)
		if !ok {
			return result, errPolicyPreparation
		}
		result.rules = counter.RulesCount()
		return result, nil
	})
}
