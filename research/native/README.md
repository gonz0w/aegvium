# Bounded native engine repeat

Status: observed research execution, not lab/stack/appliance acceptance. The [receipts](engine-observations.json) preserve exact candidate/tree, runtime input hashes, host Go/QEMU identity, binary/base/patch hashes, nonroot UID, named cases and cleanup. Raw private logs/reports remain in ignored `.tools/native-runs`; their hashes bind the shared observations.

The image pin is inherited from Nomvium’s `tools/openbsd-image.json`; this research uses an independently verified copy, never its active image or process.

| Runtime candidate | Actual observation |
| --- | --- |
| `632620ec23e9a59f8b4539371b338d6d559dd19e` | Boot-stage controlled abort: result failed as intended; group teardown and unchanged base/source verified |
| `632620ec23e9a59f8b4539371b338d6d559dd19e` | First native execution: all 13 admitted cases passed; patches/reboot/nonroot UID and teardown verified |
| `929ac75efaf93dca92ab82d6dd5a784e5c5b9985` | Corrected supervisor: fresh full repeat, all 13 cases passed; patches/reboot/nonroot UID and teardown verified |
| `929ac75efaf93dca92ab82d6dd5a784e5c5b9985` | Auth-stage controlled abort after successful rotation: result failed as intended; group teardown and unchanged base/source verified |

The supervisor correction moves startup-receipt writing and selector registration inside its cleanup boundary; a host regression forces real receipt I/O failure and verifies child reaping. Earlier native observations remain historical rather than being relabeled as tests of this correction. This documentation/evidence commit follows those runtime candidates; it does not represent a new native run. Runtime/build inputs must match the recorded hashes before reusing an observation.

Both full repeats ran the same host Go 1.27.2 CGO-disabled OpenBSD amd64 test binary on OpenBSD 7.9 as UID 32767. Native installed-key/signify checks authenticated the offline 34-patch baseline, and a changed boot time was observed before engine execution. The [official errata](https://www.openbsd.org/errata79.html) and [syspatch manual](https://man.openbsd.org/OpenBSD-7.9/syspatch.8) explain the patch mechanism; the dated pin is not a future latest-patch claim.

Seven engine request cases, four CRS smoke cases, invalid configuration and reader-error characterization passed with synthetic in-memory backend assertions. The reader-error case confirms the upstream implicit-200 behavior with zero backend receipts; an appliance integration still needs explicit error responses and inspection-aware readiness. No application HTTP listener, relayd, TLS, full CRS corpus or performance/stability qualification is claimed. The source-build observation below is separate from these earlier cross-build repeats. The image comes from a third-party builder; installed patch authentication does not prove its complete original build lineage.

## Repeating the fixture

Read the [PRD/EDD/Test Design](../../docs/milestones/M1/NATIVE-ENGINE.md) first. Run `make tools research-tools` and use the decoded image pinned by [image-pin.json](image-pin.json). `python3 tools/native-image.py SOURCE base-7.9-reviewed` creates a new independent read-only base. Do not reuse an active sibling checkpoint.

Prepare a private regular-file copy of the pinned builder bootstrap key at `.tools/native/bootstrap.key` (0600). Prepare the reviewed 36-file patch mirror in `.tools/openbsd-patches` (0700), using verified copies or `python3 tools/openbsd-patches.py fetch`; run its `verify` command. The controller independently verifies these hashes before launch. Public bootstrap material remains outside Git; fresh per-run keys are generated and the bootstrap access is revoked inside each guest.

Commit/sign the clean candidate, run `make verify`, then `make research-native`. QEMU, SSH and the reviewed host toolchain are prerequisites. The controller always rebuilds the test binary, derives its own loopback endpoint, restricts guest egress and enforces a shared 900-second guest budget. It retains failures and requires teardown/source/base receipts. `--inject-failure boot|ssh|auth|transfer|test` exercises controlled stage aborts, not every low-level failure.

Native SSH/transfer/test abort arms and comprehensive low-level failure coverage remain unobserved. Signed official image provenance, native connector builds and actual connector/CRS corpus qualification remain open in #12/#14/#15/#17. Nothing in this receipt closes a phase gate or authorizes service deployment.

## Offline native source build

[Source-build observations](build-observations.json) retain both attempts. Candidate `eb67c2d9aa0a92f82d18919747191728faa6f1a4` exhausted its shared 900-second deadline while compiling; it produced no completed binary or native test pass. Teardown and unchanged source/base passed. This failure remains evidence.

Fresh candidate `b57423a70f45f2256e68a355d6b426ef119313cb` used a separately bounded 1800-second cold-build profile with the same two CPUs, 2 GiB RAM, restricted network and storage limit. It compiled the vendored engine fixture offline on OpenBSD 7.9 amd64 with Go 1.27.2 as UID 32767, then passed all 13 admitted cases using the newly built binary. Its SHA-256 is `2e3ed433dbf6d91150128103068eaa4aad9864db859ae5d19b3a3472281956ae`; the host cross-build control remains separately recorded. Authenticated patches/reboot, bootstrap revocation, unchanged source/base and owned-group teardown passed.

Prepare the pinned SDK using `python3 tools/native-build.py fetch`; commit/sign the clean candidate, run `make verify`, then `make research-native-build`. Only four admitted module source files are vendored; the private archive contains 745 regular files including dependencies and licenses. Shared receipts bind the full private file manifest by a documented hash encoding. No SDK/vendor assets are appliance payloads. Compilation failure cannot fall back to the host binary.

These receipts belong to the exact runtime candidates above. Subsequent evidence/documentation commits do not claim another native run; runtime/build hashes must match before reusing a result. Engine source-build feasibility is observed, while connector builds, signed original image lineage, comprehensive failure coverage and phase gates remain open.

## Explicit inspection-error experiment

[Adapter observations](error-adapter-observations.json) record candidate `3f6c03dc2e7ac9d12fa6ca0d451bfa0791970c18` passing all 20 admitted cases on OpenBSD 7.9 amd64 as UID 32767. Seven new cases exercise the test-only completion wrapper: benign empty/POST, immediate/partial read errors, URI/body denial and logged DetectionOnly forwarding. Both read errors returned generic 500 with zero synthetic backend receipts; the unmodified middleware's implicit-200 characterization remains a separate passing observation.

The controller cross-built this candidate on the host and executed it natively; this run is not a new native source-build observation. Authenticated patch baseline/reboot, fresh credentials/bootstrap rejection, unchanged source/base and owned-group teardown passed. Current fixture admission requires 20 named cases; earlier 13-case observations remain historical. This is not an actual HTTP proxy, inspection readiness, response inspection or relayd/TLS/parser qualification. See the [scoped packet](../../docs/milestones/M1/ERROR-ADAPTER.md). Later documentation/evidence changes do not claim another native run; runtime inputs must match the recorded hashes.

## Restricted PROXY prefix parser

The [parser packet](../../docs/milestones/M1/PROXY-PARSER.md) and [receipts](proxy-parser-observations.json) record all 45 admitted leaves passing as UID 32767 in an owned patched/rebooted OpenBSD guest (20 engine plus 25 parser). The restricted v1/TCP4 parser rejects malformed/unselected prefixes and preserves following application bytes. Host cross-build execution, patch/bootstrap/source/base and teardown gates passed; this is not a new native source build or listener/identity qualification. Current ordinary admission is 45; previous 13/20-case receipts retain their original scope. Connected admission/result remains separately 63/failed 59. No socket, relayd wire comparison, peer authentication or readiness behavior is implemented here.

## Deadline-setting connection handoff

The [handoff packet](../../docs/milestones/M1/PROXY-ADAPTER.md) and [receipts](proxy-adapter-observations.json) record all 55 native leaves passing: 20 engine, 25 parser, eight pipe and two owned-guest TCP controls. Prefix timeouts closed peers; successful handoff preserved buffered application bytes and the real transport peer. The initial host closure-helper failure is retained separately. Guest patches/reboot, bootstrap rejection, nonroot execution, source/base and teardown gates passed. This is host cross-build execution, not a native source build or stock relayd PROXY comparison. Ordinary admission is now 55; earlier receipts retain their scopes. Connected relayd admission/result remains separately 63/failed 59. Readiness, bounded listener admission, header/Coraza identity mapping and sender containment remain open.

## Bounded listener lifecycle

The [listener packet](../../docs/milestones/M1/PROXY-LISTENER.md) and [receipts](proxy-listener-observations.json) record 63 ordinary native leaves passing: prior 55 plus six synthetic-listener/two owned-guest TCP cases. Two workers bounded accepted-but-undelivered connections; valid handoff progressed beside a slow prefix, shutdown joined workers, and synthetic engine readiness gated preparation/transfer. Bare HEAD was rejected on the strict TCP data listener. Guest patch/reboot/bootstrap/source/base and VM teardown passed. This is host cross-build execution, not a fresh native source build, HTTP health wiring or stock-relayd PROXY comparison. Ordinary admission 63 is separate from stock-relayd connected admission 63 and its historical failed 59/63 result. Header/Coraza identity mapping and sender containment remain open.

## Separate receiver readiness endpoint

The [readiness packet](../../docs/milestones/M1/PROXY-READINESS.md) and [receipts](proxy-readiness-observations.json) record 73 ordinary native leaves passing: prior 63 plus eight handler/two TCP health leaves. A distinct endpoint returned bodyless bare HTTP/1.0 HEAD, tracked synthetic engine transitions, and remained reachable with 503 after data receiver shutdown/failure. Bare HEAD stayed rejected on the data role; workers/HTTP server joined and both ports became unreachable. Guest patch/reboot/bootstrap/source/base and VM teardown passed. Host tooling/source export passed with native TCP capability skips; this was a cross-built execution, not a new source compilation. The initial stale local admission-count assertion failure is retained. Stock-relayd connected admission/result remains separately 63/failed 59. No checker wiring, loaded-rule readiness or sender authentication is qualified.

The [probe-core host receipts](readiness-probe-host-observations.json) record 11 host pipe/validation/dial-error leaves plus local verification/tooling. This adds no native run; ordinary admission remains 73 and prior native receipts remain candidate-specific. CLI exit semantics and stock-relayd wiring are untested.

[Standalone checker host receipts](readiness-checker-host-observations.json) retain ten wrapper/invalid-argument process leaves and local tooling. Positive network exits, native probe TCP, signals and stock relayd behavior are untested; no new native evidence or admission count is added.

[Native checker receipts](readiness-checker-observations.json) retain 90 passing ordinary leaves, including eleven core/six native process cases, a verified helper transfer, seven silent zero/two silent one exits and three listener-cleanup receipts. Missing helper is an explicit launch error. Patch/reboot/bootstrap/nonroot/source/base/VM teardown passed. Both binaries were host cross-built; no source-build claim. Ordinary admission is now 90; stock-relayd connected admission/result remains separately 63/failed 59. Daemon wiring/account/signal/positive-error exit behavior remains pending.

[Stock relayd contract receipts](relayd-checker-contract-observations.json) retain initial and diagnostic failures. Both 90-case ordinary subsets/syntax and daemon/VM cleanup passed, but the six-state contract was not admitted: diagnostic self-TERM reported UP instead of required DOWN. Exit 2 also reported UP. Exact signal/wait-status mechanism and script account qualification remain unresolved; no forwarding or health-transition wiring acceptance. Each receipt is source-bound to its own candidate.

## Connected readiness and health faults

The [readiness/forwarding packet](../../docs/milestones/M1/READINESS-WIRING.md) links [first-matrix receipts](readiness-wiring-observations.json) and [health-fault receipts](readiness-health-fault-observations.json), each bound to its own signed candidate. The first five phases qualified down/ready/down/recovered/terminal receiver Close using fresh ingress and separate health/inspection/sink witnesses. The later eight phases qualified silent, malformed, redirect and refused health with data kept ready, three health-mode recoveries and a final terminal health-listener closure.

All four fault helpers returned 0 and table state eventually became DOWN. Fresh post-DOWN ingress produced no bytes or events; four independent direct data controls passed. All four polling-window ingress requests forwarded with before/after table snapshots UP. These results establish eventual removal for the tested peers, not instantaneous revocation. Existing connections remain unqualified; fresh process recovery is measured separately below. Ninety ordinary cases, authenticated patch/reboot/bootstrap/source/base and graceful fixture/daemon/listener/socket/VM cleanup passed separately. Cross-built execution is not a new native source-build or installed-lineage claim. Original script failures and historical failed 59/63 connected traffic remain unchanged; broad M1 acceptance stays open.

## Checker replacement and restoration

[Replacement receipts](checker-replacement-observations.json) and the [scoped packet](../../docs/milestones/M1/READINESS-WIRING.md) admit seven phases with the inspection path kept ready. Missing executable returned a shell launch error 127 and table DOWN despite healthy health. A controlled exit-2 replacement made table state UP and forwarded an inspected benign request while the saved original helper returned 0 against silent health; this is unsafe health classification, not an uninspected bypass claim. Exact script identity/UID 89, original-helper restoration hash/root owner/0555 mode, three DOWN ingress zero-delta witnesses and three independent direct data controls passed. Ninety ordinary native cases and independent patch/reboot/bootstrap/source/base/process/listener/socket/VM gates passed separately. The unchanged stock-launched helper UID, restart/existing connections, sender/native lineage, real rule readiness/full CRS and runtime adoption remain open. Successful characterization does not accept the unsafe policy; prior failures and UP polling-window forwarding remain retained.

## Fresh fixture generation recovery

[Generation recovery receipts](generation-recovery-observations.json) record three distinct startup-unready fixtures recovering benign inspection/sink and denied inspection/no-sink traffic behind one continuing stock relayd parent. Generation one stopped gracefully after terminal health refusal; generation two was deliberately SIGKILLed with owned ancestry/UID checks, retaining a stale ready receipt and observed shell wait 137; generation three recovered and stopped gracefully. Both process-absent DOWN gaps rejected fresh ingress. Six inspection/three sink events were admitted across the three ready generations.

Ninety ordinary native cases and final patch/reboot/bootstrap/nonroot/source/base/process/listener/socket/VM gates passed. Two fixture tests completed zero; the intentional crash interrupted the other. Sixty-two source fingerprints bind the signed runtime candidate; fifty local checks and host test/vet/race/advisory/cross-build/export passed. Run `make research-relayd-generations` from a signed clean candidate with the reviewed disposable baseline. The [scoped packet](../../docs/milestones/M1/READINESS-WIRING.md#fixture-generation-recovery-packet) defines controls and limits. Fresh process recovery does not qualify persistent/in-flight semantics, worker identity continuity, kernel wait-status attribution, real rule readiness or runtime adoption.
