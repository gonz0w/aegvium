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

## Existing connector source comparison (2026-10-14)

The [behavior/maintenance review](connector-comparison.md) extends inspection to ten immutable coraza-caddy source blobs; [fingerprints](../../research/coraza/connector-source-comparison.json) verify the unchanged pinned LICENSE/go.mod and retain function anchors. The 181 declared requirements are 181 module-manifest entries, including test/build inputs, not loaded runtime dependencies or footprint evidence. No Caddy module is installed/imported or added to the research graph; its native comparison and complete dependency/NOTICE review remain gates in the [proposed ADR](../architecture/adr-0001-ingress-inspection.md).

## Runnable lab companion advisory snapshot (2026-10-14)

The signed-source scan for [LP-01–04](../milestones/M1/LAB-COMPANION.md) reports zero affected reachable symbols/imported packages, but five module-only `golang.org/x/net` HTTP/2 advisories at v0.58.0 (fixes reported v0.60.0). [Receipts](../../research/native/lab-proxy-observations.json) retain exact IDs and raw scan hash. No dependency pin changed or package was added. This is a scoped call-graph result, not a clean-graph claim; selected-graph update/provenance review and fresh scanning remain required before runtime adoption or Caddy integration.

## Isolated connector execution graph (2026-10-14)

The new [separate comparison module](../../research/connector/README.md) follows [ADR-0002](../architecture/adr-0002-isolated-connector-comparison.md) and the reviewed [loaded graph/legal fingerprints](../../research/coraza/connector-dependencies.json). The earlier source-only assessment remains historical. Importing the pinned connector loads 153 third-party modules on the host and 152 on OpenBSD/amd64; these are package-loading inputs, not a linked-symbol distribution SBOM. The actual test package graph contains 989 target packages including standard library and generated test packages. The companion module/pins are unchanged.

Private unmodified fixture execution is within this review. MPL-2.0 MySQL code is a loaded Caddy PKI input; external executable distribution requires the covered source and recipient notices described by the [upstream MPL FAQ](https://www.mozilla.org/en-US/MPL/2.0/FAQ/). Apache/MIT/BSD/CC0 terms, nested licenses, CoreOS/Prometheus/grpc/yaml notices and Go AUTHORS/PATENTS were inspected. Brand and Windows distribution assets have separate terms and are excluded from the imported OpenBSD source/embed inputs. No upstream source or binary is published here; future distribution needs a complete applicable notice/generated-asset review.

The [advisory record](../../research/connector/advisory-review.json) preserves an initial inadequate scan whose two-module SBOM omitted test-only imports. Moving the real adapter into ordinary source fixes coverage: host and OpenBSD-targeted scans load 155/154 SBOM modules including main/stdlib, with nine advisory IDs, eight imported-package IDs and seven symbol-level IDs. Findings include x/net HTTP/2 and OpenTelemetry; CEL has package-level findings and unmaintained OpenPGP is module-only. Reported fixes and exact versions are retained. These static paths do not prove exploitability in this HTTP/1.1 fixture, but prohibit a clean-graph or adoption claim. Pins stay fixed for an attributable comparison; reviewed remediation is required before appliance adoption.

## Compatible advisory refresh (2026-10-14)

[ADR-0003](../architecture/adr-0003-research-advisory-refresh.md), [reviewed deltas](../../research/dependency-refresh.json) and [fresh native/scanner receipts](../../research/native/dependency-remediation-observations.json) supersede the original graphs for current research. Thirteen connector selected versions and seven companion selected versions change, with shared updates; no module paths are added/removed. Eleven changed versions contribute connector target packages; x/mod and upstream logtest remain selected/unloaded. All 203 reviewed target legal files retain identical bytes. Existing distribution/NOTICE/MPL obligations persist.

x/net v0.60.0 and the OpenTelemetry log family v0.21.0 remove the seven prior symbol-level IDs. The attempted CEL v0.30.0 fix is incompatible with pinned Caddy v2.11.4; its ignored failed package-loading attempt is retained by hash and never counted as a clean scan. Retain CEL v0.28.1/package-only GO-2026-6094 and x/crypto v0.57.0/module-only GO-2026-5932 (deprecated, unimported openpgp; no reported fixed version). Full server/framework refresh and these residuals still block adoption.

`make research-advisories` performs fresh symbol scans including tests for both modules on host and OpenBSD-targeted source. Each scanner SBOM must exactly match independently loaded module/version identities; failed/incomplete scans and new or more reachable findings reject the gate. Current results: companion zero findings; connector two module IDs/one package ID/zero symbol IDs on both targets. The scanner inventories loaded package graphs; broader selected graphs include unloaded inputs and are reviewed separately. Zero loaded-source findings do not certify the entire selected graph. Narrow residual exceptions authorize this research regression check only, not a security release or appliance adoption. Native controls and offline connector compilation retain prior semantics; host-cross-built engine/companion execution is separate from native-built connector evidence.

## Configured reverse-proxy inputs

[ADR-0004](../architecture/adr-0004-configured-caddy-comparison.md) reviews explicit Caddy reverse-proxy/filesystem registration. The actual transport adds github.com/pires/go-proxyproto v0.12.0 to loaded inputs; it was already in the selected graph. Its Apache-2.0 LICENSE, archive/module sums and VCS commit are in the [updated inventory](../../research/coraza/connector-dependencies.json). All old versions/legal bytes and the companion graph remain unchanged. Target inputs now include 153 modules/204 legal files; the extra module does not enable upstream PROXY output in this fixture. Private unmodified execution remains the review boundary; distribution obligations persist.

[Fresh native/advisory receipts](../../research/native/configured-caddy-observations.json) retain complete host/target loaded-source scans with zero symbol-level IDs and the two prior residuals. The configured server adds native TLS/reload evidence without declaring either residual resolved or certifying the broader selected graph.
