# ADR-0003: remediate compatible research dependencies

Status: bounded research decision for review; appliance adoption withheld.
Date: 2026-10-14. Parent: #13/#15 and [ADR-0002](adr-0002-isolated-connector-comparison.md).

The existing connector comparison reports seven advisory IDs with reachable-symbol traces, one additional imported-package ID and one module-only ID. The companion reports five module-only x/net IDs. Preserve those historical observations, then refresh the compatible transitive versions in both isolated research modules before repeating the admitted controls.

Use x/net v0.60.0 and the OpenTelemetry log family v0.21.0. The [reviewed refresh manifest](../../research/dependency-refresh.json) records all thirteen selected-version changes, checksum-database archive/module sums, exact VCS origins and legal-file hashes. Eleven changed versions contribute target packages; x/mod and the upstream logtest module are selected but not loaded. There are no new module paths. All 203 target legal-file contents remain unchanged, including existing MPL/NOTICE/PATENTS obligations. This authorizes private unmodified research builds only; distribution review remains separate. Coraza v3.8.1, CRS v4.25.0, coraza-caddy v2.6.2, Caddy v2.11.4 and Go 1.27.2 remain fixed.

This decision supersedes ADR-0002's unchanged-companion restriction only for the reviewed transitive refresh. Both research modules remain isolated. The full selected graphs retain 520 connector and 41 companion entries including their main modules; these include unloaded test/build inputs and are not runtime SBOM counts. The companion changes seven selected versions, with three appearing in its explicit requirements; its prior x/crypto selection was v0.55.0 rather than the connector's v0.56.0.

The initial ignored staging attempt deliberately tested CEL v0.30.0, the reported fix. It fails package loading because Caddy v2.11.4 supplies Interpretable values to the changed NewCall API. Updating only the affected OpenTelemetry modules also fails against older HTTP/stdout log exporters; the compatible selection moves those log exporters together. Retain the failed attempt's hashes and reason. A package-loading failure is not a completed advisory scan.

Keep CEL v0.28.1's imported-package finding explicit. A compatible Caddy/connector upgrade needs its own source/behavior review; do not patch upstream code, weaken scanner coverage or claim this batch resolves it. The deprecated x/crypto/openpgp advisory has no reported fixed version and remains module-only because that package is not imported. Neither residual is accepted for appliance adoption.

Add a local advisory gate that compares the scanner's module SBOM with independently loaded host/target package graphs, rejects incomplete/failed scans and new or more reachable findings, and reports the narrowly recorded residuals. Zero findings must follow complete graph admission rather than scanner exit status. Its exceptions allow this research regression check to run; they do not approve a security release.

Repeat host tests/vet/race/cross-builds, the exact native connector wire/reload matrix, ordinary engine controls and actual relayd/companion paths. Bind fresh output identities separately from older native compilation. Native compilation of the refreshed connector uses the existing offline unprivileged profile and unchanged predeclared limits. [Qualification and rollback](../milestones/M1/DEPENDENCY-REMEDIATION.md) define acceptance. No fixture policy or expected status/backend effect changes are authorized by this decision.

Rollback restores the previous module files and reviewed inventory from the parent revision, then rebuilds and repeats checks. That restores known-vulnerable research pins, so retain isolated lab restrictions and the explicit findings. Preserve all historical evidence; no service, product graph, installer or live network changes here.
