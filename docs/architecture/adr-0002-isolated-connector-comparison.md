# ADR-0002: isolate the existing-connector research graph

Status: bounded research decision for review; appliance adoption withheld.
Date: 2026-10-14. Parent: #13/#15 and [ADR-0001](adr-0001-ingress-inspection.md).

The pinned coraza-caddy connector needs execution evidence before choosing a custom companion. Its import alone loads 152 third-party modules on OpenBSD/amd64, including Caddy PKI, telemetry and an MPL-2.0 MySQL input. Adding it to the companion module would expand that module's selected graph even when an executable does not import Caddy.

Use a separate `research/connector` Go module pinned to coraza-caddy v2.6.2, Caddy v2.11.4, Coraza v3.8.1 and CRS v4.25.0. The prior source commit, checksum-database identities, loaded legal-file fingerprints and notice assessment are retained in the [dependency review](../../research/coraza/connector-dependencies.json). This decision follows that review and authorizes only unmodified private fixture builds/execution. It does not approve dependency redistribution or product adoption. Keep the companion's go.mod/go.sum byte-identical.

Load the real registered connector through Caddy's module context and request preparation API in an owned standard-library HTTP harness. Compare it with Coraza's public HTTP middleware under identical rules/requests/backends. This measures connector behavior; it does not run Caddy's complete server/admin/automatic HTTPS stack or substitute for relayd-connected appliance parity. Keep error rendering by the harness explicit. Do not import Caddy's standard-module aggregate, request certificates, start an installed service, or contact an external backend.

The [qualification packet](../milestones/M1/CONNECTOR-EXECUTION.md) binds request/error/response and rule-file pool reuse behavior to strict receipts. Cross-built execution on OpenBSD and native compilation remain separate claims. No published binary or dependency source accompanies this research. Before any distribution, preserve applicable license/copyright/NOTICE/PATENTS, review generated/embedded assets and satisfy the MPL source/recipient notices; see the [upstream MPL FAQ](https://www.mozilla.org/en-US/MPL/2.0/FAQ/).

Alternatives: source-only assessment leaves the main decision unmeasured; importing Caddy into the companion unnecessarily couples graphs; a full Caddy appliance deployment expands this bounded experiment. This isolated fixture gives executable evidence without selecting a runtime framework. No security or footprint superiority follows from module counts.

Rollback removes the isolated module, controller option and current recommendation; preserve historical observations. Any adoption, graph refresh, resource budget, trusted identity, full Caddy/relayd topology or installer change needs its own reviewed scope.
