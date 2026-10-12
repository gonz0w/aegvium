# First native engine repeat packet

Status: implemented bounded research controller with [recorded observations](../../../research/native/README.md); full lab acceptance remains open. The user authorized continued research on 2026-10-11 after merging PR #42. This does not accept a runtime connector or any production policy.

## PRD

NATIVE-01: repeat the pinned engine and CRS smoke tests inside an independently owned OpenBSD 7.9 amd64 disposable VM.
NATIVE-02: authenticate exact image/source/test input lineage; preserve all original failures and distinguish host build from guest execution.
NATIVE-03: isolate guest networking and credentials, bound runtime and storage, and prove teardown. No live gateway or application.

No native source-build claim: host Go 1.27.2 cross-compiles the CGO-disabled test binary. Native Go compilation and connector qualification belong to #14/#15. A passing native smoke test cannot close those issues or M1.

## EDD

- Use the [inherited image pin](../../../research/native/image-pin.json), SHA-256 verification before any boot, regular files only, no symlinked assets. The upstream is an anyvm builder, not signed official install media; installed OS/key provenance needs explicit native receipts.
- Make an independent private Aegvium base copy; never mutate a sibling cache/checkpoint. Hash the copied base before and after. Mode 0400 base, 0700 run directories, 0600 private keys. Record source/tree and compiled test SHA-256.
- QEMU TCG, 2 vCPU/2 GiB, one owned overlay, restrict=on user networking, one dynamically reserved loopback-only SSH forward, no bridge/host mount/LAN interface or guest egress. TCG timing is functional evidence only.
- Supervisor owns only its process group. Controller EOF or a 15-minute total deadline initiates TERM, bounded wait, then KILL if needed. Verify group disappearance; retain failed teardown rather than report success.
- The inherited public builder login is bootstrap-only. Generate fresh per-run keys, require public-key-only SSH, disable forwarding, revoke inherited authentication and prove old authentication is rejected while fresh access succeeds. Loopback target is derived from owned QEMU; no arbitrary remote SSH target is accepted.
- Pin a reviewed official syspatch set and key before boot, transfer the local mirror, authenticate native installed key against pinned official public material, verify native signify and patch hashes, apply only to the owned disposable image, reboot and record receipts. Guest egress stays disabled. Do not reuse a sibling's patched active guest. The implementation below pins a dated patch set; official installed-key/signify authentication remains a guest gate.
- Transfer only the hashed test executable and synthetic inputs into an owned guest path. Run with an unprivileged fixture user after setup, execute the engine and CRS smoke cases, capture exit/status/case counts and OS/patch receipts, then reap owned processes and stop the VM. No rc.d service is installed or enabled.

## Test Design

| ID | Observable postconditions |
| --- | --- |
| NATIVE-01 | Every admitted engine/CRS case executes on the guest, matching test input hashes; exit/status and skipped cases recorded |
| NATIVE-02 | Exact source/tree, host Go, binary SHA, image/patch/key receipts and unchanged independent base hash; no native-build claim |
| NATIVE-03 | Negative checks reject symlink/hash/target drift; inherited login fails, fresh login succeeds; loopback/restricted networking verified; timeout and controller EOF kill/reap owned group |

Failure injection must exercise boot/SSH/auth rotation/transfer/test failures and deadline/EOF teardown. Never treat a failed SSH attempt alone as credential revocation. Retain raw private logs locally and sanitize shared receipts. A gate remains failed if cleanup cannot be observed.

[Official OpenBSD release](https://www.openbsd.org/79.html), [errata](https://www.openbsd.org/errata79.html), and [QEMU networking documentation](https://www.qemu.org/docs/master/system/invocation.html) are primary references. Nomvium's independently reviewed harness is a pattern, not an adopted Aegvium harness or evidence of Aegvium execution.

## Implemented preparation

`tools/lab-supervisor.py` adapts the BSD-licensed Nomvium process-group supervisor with a mandatory 1–900 second deadline. Host regression tests exercise controller EOF, deadline expiry, normal child exit and TERM-resistant child escalation. These establish host lifecycle behavior only. Image admission is implemented; guest execution evidence is recorded separately from these host checks.

### Independent image admission

`python3 tools/native-image.py SOURCE NAME` streams and checks the pinned decoded qcow2 into a new `.tools/native/NAME` directory. It rejects symlinked source paths, nonregular files, hash mismatches and existing destinations. The base is private/read-only; the receipt explicitly records third-party provenance and no guest execution. This admits decoded image bytes only: compressed archive, bootstrap credentials, patches and guest lifecycle are separate checks before any boot.

### Native controller

`make research-native` requires a clean committed candidate, the independently admitted base, a hash-verified private bootstrap-key copy and the verified patch mirror. It cross-compiles the exact candidate before launch, then owns QEMU through the bounded supervisor. Only the generated loopback endpoint is accepted. The per-run QEMU snapshot lives in its private run directory; a 4 GiB file-size bound applies to the supervisor/QEMU. A shared 900-second guest deadline clamps every SSH operation and readiness loop. Cross-build and input verification precede that guest deadline.

Fresh public-key access must succeed, the public bootstrap key must receive an explicit public-key authentication rejection, and fresh access must still succeed. The pinned October 8 patch set has 34 assets; native checks authenticate both the installed official key and manifest, verify signify and all asset hashes, apply the offline mirror, require no pending patches and a changed boot time. No current/latest patch claim is made. The release/patch receipts authenticate an installed baseline, not the original third-party image's complete build history.

The transferred binary must match its host digest and run as nonroot `nobody`. Admission requires all 13 named engine/CRS cases and their two parent groups, no unknown/duplicate/skipped/failed results, exact OS/patch/kernel/binary receipts and verified cleanup with unchanged source/base. A pass remains a native execution repeat of a host cross-build, not a native source build, actual relayd integration or full CRS corpus.

`--inject-failure boot|ssh|auth|transfer|test` triggers a controlled abort after launch or the named stage for cleanup exercises; these are controller aborts, not simulations of every possible low-level guest failure. Shared reports must explicitly distinguish stage injections, host failure-path tests and actual native receipts. Private logs and original failed reports remain in `.tools/native-runs`.

Generic QEMU/SSH/patch code and patch pins are adapted from Nomvium's BSD-licensed tooling; original notices are retained in LICENSE. The guest scripts are only supplied by the owned controller and must never be invoked against a live machine. Native execution does not close #12/#14 or any phase gate until all their acceptance criteria are met.

Observed native abort stages are boot and auth; SSH/transfer/test stage aborts and comprehensive low-level guest failure injection remain outstanding. Host tests cover EOF/deadline/TERM resistance/startup-receipt failure and misleading authentication/result rejection. The packet’s broader failure criteria are not declared complete.

## Bounded native source-build slice

`make research-native-build` uses the same independently owned, patched, rotated and restricted guest with the existing 900-second total budget. Before launch, `tools/native-build.py` verifies the official Go 1.27.2 OpenBSD amd64 archive by pinned SHA/size, verifies cached modules and vendors an independent source copy with downloads disabled. Only regular files are exported; original source must remain unchanged. Vendor licenses remain in the private source bundle. This covers the existing engine module; connector-wide distribution review remains open.

The guest verifies both archive hashes before extraction, checks Go version/OS/architecture, makes compiler/source root-owned and readable, and compiles as nonroot with CGO off, `GOTOOLCHAIN=local`, `GOPROXY=off`, vendored mode, telemetry off and two compile workers. Output/cache is private to the fixture user. Receipts distinguish host cross-build hash from native output hash. Only a successful native compile plus the complete 13-case repeat, patch/reboot and teardown/source/base receipts can pass this slice. A deadline or compile failure is retained as failure; no increased budget or stale cross-build fallback is allowed. It does not accept the connector, signed official image lineage or full #14 outcome.

Host negative tests check compiler checksum/size drift, missing/malformed native build receipts and failed native transfer/compile. Native execution is source-bound after a signed clean candidate. The [official Go download manifest](https://go.dev/dl/?mode=json) supplies the archive pin. Prepare it using `python3 tools/native-build.py fetch`; guest egress stays disabled.
