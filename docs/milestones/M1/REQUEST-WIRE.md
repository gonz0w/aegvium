# Bounded HTTP/1.1 request wire policy

Status: authorized bounded research under #15/#16/#21; no product protocol adoption.

## PRD

RW-01 (WAF-02/03/04/05): the close-only companion must reject declared and undeclared request trailers before inspection or backend forwarding. Trailer fields are outside the admitted header/body interface; silently forwarding them creates an uninspected application input. Reject with generic 400 and zero backend effects. Preserve ordinary fixed/chunked JSON, attack denial and existing framing characterization.

RW-02: exercise identical raw HTTP/1.1 messages over verified companion TLS, directly with a synthetic PROXY control and through stock TCP relayd. Compare exact status, complete response count, server close and independent backend body/authority/path/trailer observations. Pipelined second requests must have no response or backend effect. A client deadline is failure, never evidence of safe rejection. Duplicate equal lengths and CL+TE normalization remain explicit observations, not strict wire rejection claims.

## EDD

Reject nonempty Trailer declarations/maps before reading and recheck the trailer map after bounded body EOF, since Go can discover undeclared trailers while consuming chunked data. Initialize the original request trailer map before the identity wrapper takes a shallow copy, so EOF updates remain visible across that copy. Retain existing byte/deadline/admission bounds, framing parser and response contracts. No new dependencies, listener, CLI argument or external configuration. Keep old TLS cases unchanged. A separate opt-in native fixture uses the actual offline-native-built identity-enabled CLI, fixed owned relayd profile and both transport controls after prior PF matrices restore their state. Direct prefix controls do not authenticate a proxy or establish a sender boundary.

## Test Design

RW-03: retain a source-bound failing host observation if the existing handler forwards trailer input; fix and rerun within this branch. Cover declared/undeclared/empty/forwarding/authorization trailers, invalid framing, benign/hostile chunked bodies, cap+1, truncated inputs, CL/TE permutations, duplicate lengths, body on GET, pipelined benign/hostile second messages and fresh recovery. Require verified TLS, identical sent bytes/hash, exact finite response, Connection close, EOF before client deadline, independent backend counts and exact admitted body/path/authority with zero trailers or spoofed metadata. Host direct tests are tooling evidence; OpenBSD actual CLI/relayd execution is separate.

Strict admission requires exact named Go tests, ordered typed rows, native build/install/execution identities and nonroot UID, preserved prior semantic matrices, complete process/listener/public/private asset cleanup and source/base/VM teardown. Keep failed attempts immutable; do not weaken a hostile zero-effect criterion to admit forwarding. Run make verify, Go regression/vet/race/cross and advisory policy; signed commits and DCO precede native execution.

## Compatibility and rollback

Trailers become explicitly unsupported in this laboratory profile. No HTTP/2/3, persistent/streaming support, full smuggling/CRS coverage, native race, production trust/privilege/resource policy or safe retry acceptance follows. Existing application effects cannot be undone by a rejected response. Rollback restores the prior handler and omits the separate request-wire mode, preserving all evidence. No live networks/services, installer schema or release changes.

## Current evidence and blocker

Host direct verified-TLS controls pass all twenty-six raw-wire rows after the repair, alongside full Go/vet/lab race/cross/advisory policy and 103 local checks. [Failed host discovery/first repair](../../../research/native/request-wire-host-failure.json) remain separate uncommitted source-hash-bound observations.

The [failed native attempt](../../../research/native/request-wire-native-failure.json) binds `cbc21ae71fb94c5da25580856729d518c48a874d` and run `d234e0d8-5116-4608-a6bd-0a1d61f56cfc`. Offline native fixture/checker/CLI build and 163 ordinary cases passed, then three legacy post-reload response assertions failed. Each had status zero/client error and zero effects; expected outcomes were 403/0, 421/0 and 200/1. Cause is unproven. All later native matrices, including the new fifty-two wire rows, were not executed. Cleanup/source/base invariance/teardown passed independently. Native trailer/complete profile qualification remains blocked; keep the PR draft and acceptance unchecked.

Next validation must diagnose the legacy response failure with sufficient client/daemon evidence and repeat the full candidate without changing required outcomes or retrying failures away. Security validation stays paused if an applicable access restriction prevents it; ordinary engineering and truthful evidence/tracking work can continue. No expanded cyber access, safeguard bypass or product adoption is implied.
