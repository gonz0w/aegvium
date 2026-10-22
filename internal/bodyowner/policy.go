// SPDX-License-Identifier: BSD-3-Clause
package bodyowner

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"sync"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

const policyWriterName = "aegvium_no_output_v1"
const maxPolicyRules = 65535 // Diagnostic bound only; never a resource proof.

// Complete source-owned directives. No caller policy, exclusions, filesystem,
// log path or Include can be appended by this constructor.
const policyDirectives = `Include @coraza.conf-recommended
Include @crs-setup.conf.example
Include @owasp_crs/*.conf
SecRuleEngine On
SecRequestBodyAccess On
SecRequestBodyLimit 4097
SecRequestBodyInMemoryLimit 4097
SecRequestBodyLimitAction Reject
SecResponseBodyAccess Off
SecAuditEngine Off
SecAuditLogType aegvium_no_output_v1
SecDebugLogLevel 0
`

const policyBinding = "aegvium-policy-v1\ncoraza-v3.8.1:h1:dMV55FbMR2vOks/acrT43RShR+VkzU6jwp+XPdxay8o=\ncrs-v4.25.0:h1:tqFO1lfVpTiyWtlN618OXpZMfw+nnN0Q4///W5W+/HM=\nfs=embedded;no_fs_access;debug=noop;errors=noop;body=4097;memory=4097;writer=aegvium_no_output_v1\n"

var errPolicyPreparation = errors.New("engine policy unavailable")

type ownedPolicy struct {
	pin       string
	ruleCount uint32
}

func policyPin() string {
	hash := sha256.Sum256([]byte(policyBinding + policyDirectives))
	return hex.EncodeToString(hash[:])
}

// Stateless and resource-free, including Init: NewWAF initializes its selected
// writer even with audit Off. Never dereference/format/retain payload or config.
// Fixed coordinator outcomes remain separate from product audit export.
type noOutputAuditWriter struct{}

func (noOutputAuditWriter) Init(plugintypes.AuditLogConfig) error { return nil }
func (noOutputAuditWriter) Write(plugintypes.AuditLog) error      { return nil }
func (noOutputAuditWriter) Close() error                          { return nil }

var _ plugintypes.AuditLogWriter = noOutputAuditWriter{}

type policyConstruction struct {
	factory transactionFactory
	closer  io.Closer
	rules   int
}

// Copies alias one consumed attempt/retained slot. Synthetic fixtures may own
// isolated states; the tagged production binding has exactly one global state.
type policyStartup struct{ state *policyStartupState }
type policyStartupState struct {
	mu        sync.Mutex
	attempted bool
	held      policyConstruction
}

func newPolicyStartup() policyStartup { return policyStartup{state: &policyStartupState{}} }

func (p policyStartup) hold(known policyConstruction) {
	p.state.mu.Lock()
	// The closed production builder creates one WAF. Retain known references
	// before any later capability method can fail/panic. Never close them here.
	if p.state.held.factory == nil {
		p.state.held.factory = known.factory
	}
	if p.state.held.closer == nil {
		p.state.held.closer = known.closer
	}
	p.state.mu.Unlock()
}

func (p policyStartup) construct(build func() (policyConstruction, error)) (*Owner, error) {
	if p.state == nil || build == nil {
		return nil, ErrInput
	}
	p.state.mu.Lock()
	if p.state.attempted {
		p.state.mu.Unlock()
		return nil, ErrStopped
	}
	p.state.attempted = true
	p.state.mu.Unlock()
	var result policyConstruction
	var err error
	panicked := invoke(func() { result, err = build() })
	p.hold(result)
	if panicked || err != nil || result.factory == nil || result.closer == nil || result.rules <= 0 || result.rules > maxPolicyRules {
		return nil, errPolicyPreparation // No error/panic/configuration text escapes.
	}
	o, _ := newEngineOwner(result.factory, result.closer)
	o.state.engine.policy = &ownedPolicy{pin: policyPin(), ruleCount: uint32(result.rules)}
	p.state.mu.Lock()
	p.state.held = policyConstruction{} // Sole engine owner now owns both aliases.
	p.state.mu.Unlock()
	return o, nil
}
