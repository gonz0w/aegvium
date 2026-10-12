# Engine, rules and connector dependency review

Dated 2026-10-11; research-only review for M1-01. Exact source tags/commits, license/module-file hashes and links are in [upstream pins](../../research/coraza/upstream-pins.json). No installed runtime dependency or connector ADR is accepted.

## Candidates and lineage

| Candidate | Reviewed pin | License | Research implication |
| --- | --- | --- | --- |
| Coraza engine | v3.8.1 | Apache-2.0 | Public HTTP middleware is usable for the spike; reader-error response needs explicit design |
| coraza-caddy connector | v2.6.2 | Apache-2.0 | Pins engine v3.8.1, Caddy v2.11.4 and embedded CRS v4.25.0; Go module baseline 1.26 |
| Coraza CRS bundle | v4.25.0 | Apache-2.0 | Selected for bounded comparison with Caddy; embedded rule inputs individually hashed |
| Upstream CRS latest observed | v4.30.0 | Apache-2.0 | Separate release pin, not silently substituted for the selected bundle |

Tagged engine/connector releases were observed recently, but a tag is not an SLA or proof of OpenBSD qualification. Source refs are immutable in our manifest; upstream can move tags, so deliberate refresh must compare commits/hashes. The CRS bundle's mage-build version file names Coraza v3.5.0 for its own build tests; this does not override the actual engine selected by Aegvium's Go module graph. Never infer the loaded rules from a module graph's test-only older CRS dependency.

The Caddy module manifest has a much broader graph than the engine spike. That declaration does not mean every listed module executes in a proposed appliance build. Determine its actual built package graph and native maintenance footprint before selecting it. A custom Go integration reduces framework surface but transfers parser, phase, buffering, error, privilege and lifecycle responsibilities to Aegvium; neither option is adopted.

## Loaded packages and licenses

The engine/CRS test package graph loads 19 third-party modules. [Loaded dependency inventory](../../research/coraza/loaded-dependencies.json) records exact versions and observed LICENSE hashes/classifications. Files show Apache-2.0, MIT and BSD 2/3-Clause terms. This is a source-file review of the loaded spike, not a completed distribution/legal review of every transitive asset, upstream NOTICE, generated schema or Caddy build.

Preserve all applicable copyrights, license text and upstream NOTICE on future source/binary distribution; Apache changes and attribution need appropriate notices. Keep the appliance's BSD license separate from dependency terms. No research binary is published by this change. Verify bundled CRS license and generated-data provenance when preparing payloads. Wider module-graph inventory from the initial spike remains historical and includes test/build-only modules; it is not the runtime SBOM.

## Advisory findings and remediation

The first govulncheck v1.9.0 symbol scan (including tests) on Go 1.27.0 returned 13 unique standard-library advisories, eight with symbol-level traces. All fixes reported Go 1.27.2. JSON scanner exit success alone does not mean no findings. [Retained summaries](../../research/coraza/advisory-review.json) preserve database timestamp, versions, IDs and raw-output hashes.

The official Go download manifest supplies the pinned Go 1.27.2 host archive checksum. Research commands now require that version in ignored .tools, leaving the system and sibling toolchains untouched. A fresh expanded test scan on 1.27.2 returned zero findings against the database last modified 2026-10-08. Static reachability is not proof of exploitation, and zero findings is not absence of unknown vulnerabilities or complete OpenBSD/Caddy/CRS security review.

## Rule smoke evidence and limits

Four host cases passed: benign query and POST retain backend access/body, SQL and script injection return 403 without backend receipts. [Input hashes](../../research/coraza/crs-inputs.json) and [host observation](../../research/coraza/crs-host-observation.json) retain this bounded result. Existing nine engine cases still pass. This is not the full CRS corpus, native execution, realistic application false-positive tuning, response inspection or OWASP Top 10 coverage.

## Updates, removal and native gates

Use a reviewed PR to refresh exact engine/bundle/connector/toolchain pins; rerun advisory, body/error and benign/attack tests, then native parser/lifecycle/corpus tests. Keep original failures and known-good inspected artifacts. No auto-update or community feed is added.

The isolated research module and research-only tools can be removed without changing an appliance because none exists. If adopted, connector/rules replacement must preserve the no-bypass and fail-closed contracts; uninstall/recovery requires its own scoped design. OpenBSD native build, TLS/backend policy, regex/body/resource behavior, package availability and least privilege remain #12/#14/#15/#17/#18 gates. CrowdSec remains optional separate work.

Primary sources: the immutable links in the pin manifest; [official Go download manifest](https://go.dev/dl/?mode=json), [govulncheck](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck), and [Go vulnerability database](https://vuln.go.dev/). Aegvium's native repeat preparation is in the [native packet](../milestones/M1/NATIVE-ENGINE.md).
