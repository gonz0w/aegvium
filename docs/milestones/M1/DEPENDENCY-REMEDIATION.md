# Compatible dependency remediation

Scope: bounded M1-01/02/03 research under #13/#14/#15/#16. Read [M1 PRD](PRD.md), [EDD](EDD.md), [Test Design](TDD.md) and [ADR-0003](../../architecture/adr-0003-research-advisory-refresh.md). No appliance adoption or external distribution.

| ID | Acceptance |
| --- | --- |
| DR-01 | Review exact selected-version/module-sum/VCS-origin deltas and every changed target legal file before pin adoption. Keep direct candidate/rules/toolchain pins and module-path sets unchanged. Preserve incompatible staging evidence and explicit residuals. |
| DR-02 | Fresh symbol scans including tests for both modules on host and OpenBSD/amd64 source targets. Scanner config, complete module SBOM and loaded version identities must match; failures, truncated scans, unreviewed IDs or increased reachability reject admission. Require no reachable-symbol IDs; retain CEL package-only and OpenPGP module-only findings. |
| DR-03 | Host Go tests/vet/race, OpenBSD cross-builds and make verify pass. Native OpenBSD repeats retain all 163 ordinary controls, forty exact connector wire rows/twenty-two reload observations, forty-two companion paths, three concurrency/reload phases and seven startup rejects. No changed expected semantics, skipped failures or fallback. |
| DR-04 | Compile the refreshed connector offline as UID 32767 using the reviewed SDK/export. Require compiler/source/output/install/execution identities, patch/reboot/access gates, unchanged source/base and complete owned socket/server/daemon/VM teardown. Separate cross-built ordinary/companion controls from native-built connector evidence. |

The existing [connector build](CONNECTOR-NATIVE-BUILD.md) fixes build/guest limits at 3000/3600 seconds before launch. Run `python3 tools/native-engine.py --lab-proxy --connector-comparison --connector-source-build` to combine separately admitted companion paths and native-built connector checks in one owned guest. Ordinary engine/checker/companion executables are host cross-built controls in this profile. Use synthetic traffic only; no installed services or external backends. Freeze tracked source throughout the run. Historical failed HTTP pipelines, half-close admission and checker findings stay unchanged.

Compatibility means unchanged admitted fixture outcomes, not complete Caddy server/TLS/identity, every protocol, full CRS, load/soak qualification or exploitability assessment. A zero-symbol scan is scoped to the loaded source/call graph and current advisory database. Remaining CEL/OpenPGP findings, full server comparison, frontend trust, original installed lineage and distribution obligations continue to block adoption.

Rollback restores both go.mod/go.sum files, the loaded legal inventories and advisory policy together from the parent revision, removes the new gate if necessary, and rebuilds/repeats verification in the isolated lab. Keep the previous advisories visible; rollback is not remediation. Retain new and old source-bound observations separately.
