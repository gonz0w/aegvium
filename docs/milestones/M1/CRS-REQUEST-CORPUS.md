# Pinned CRS request corpus research

Status: authorized bounded M1 research, under #17; not full CRS or appliance qualification.

## PRD

CC-01 (M1-02/04, WAF-01/02): expand the four-case smoke set with paired benign/SQL/script inputs in query, URL-encoded form, JSON and cookie roles. Run every vector in On and DetectionOnly. Require exact response/backend counts, preserved admitted body bytes and attack-family rule matches. This is a small synthetic corpus, not the upstream regression corpus or realistic application samples.

## EDD

CC-02: use the already pinned Coraza v3.8.1 and embedded CRS v4.25.0 configuration from the smoke test. Embed the existing 51-file manifest and verify every bundle file hash before testing; retain its manifest digest. Fresh WAF/transaction per vector and mode; no added exclusions, threshold overrides or dependency changes. In-memory HTTP middleware and synthetic backend only. Capture sorted unique matched rule IDs/phases without transaction IDs, input values or production traffic. On attacks must return 403 with zero backend receipts; DetectionOnly attacks must return 200 with one backend receipt and attack-family matches. Benign vectors in either mode must return 200 with one receipt and unchanged admitted body/query/cookie values.

## Test Design

CC-03: twelve vectors per mode (four benign plus SQL/script in each of four roles), twenty-four exact leaves. Require 941xxx script or 942xxx SQL-family matches for attack vectors; response status alone is insufficient. Retain per-leaf mode/status/backend/matched ID/phase observations. Native ordinary admission expands from ninety to 114 exact leaves without weakening prior assertions. Native report binds exact source/tree, engine/rule input hashes, unprivileged execution, patches/reboot/bootstrap/source/base and teardown. Host test/vet/race, advisory review, cross-build/export and make verify remain tooling evidence only. Preserve failed expectations; never relabel an unexpected allow/deny as the expected result to obtain a pass.

## Compatibility and rollback

No relayd, runtime policy, rule update, installer or live-network change. This studies request handling by the pinned middleware; wire parser agreement, full upstream CRS regression, realistic false positives, response phases, trust and appliance adoption remain open. DetectionOnly forwarding is intentional evidence, not enforcement. Remove the new research corpus/export/admission entries to roll back, retaining observations and earlier smoke/native failures. Native execution is a cross-built repeat unless a separate source-build run is explicitly recorded.

## Native result

[Source-bound observations](../../../research/native/crs-request-corpus-observations.json) bind signed runtime candidate `24c3e65f186f3c3c3e1d2173ef496484176e595a`, tree `6ef66dd6fc0a7448a09397b0549c36d72ef7a539`, owned run `063ad1b8-1b89-4284-bdd1-1c6be6350ce9`. All 114 ordinary native leaves passed as UID 32767: unchanged ninety-case admission plus twenty-four corpus cases. Every one of the 51 pinned bundle files matched its manifest SHA-256 before testing. No dependency, added exclusion or threshold changed.

All four roles produced the expected paired outcomes. Eight On attack-role runs returned 403 with zero backend receipts. Eight DetectionOnly attack-role runs recorded SQL/script matches and returned 200 with one backend receipt. Eight benign runs returned 200 with one receipt, preserved admitted inputs and produced no matched-rule callbacks. Across the corpus, sixteen backend receipts were observed; logged matching rules were in request phase 2. Exact sorted rule IDs/phases/status/backend observations matched the host matrix. Two raw attack values were reused across roles/modes; these are twenty-four executions, not twenty-four distinct attacks.

Authenticated 34 patches/zero pending/reboot, bootstrap rejection, source/base invariance and owned VM teardown passed without escalation. Sixty-six curated source/build/controller fingerprints match the signed runtime candidate and current files. Fifty-two local checks, host test/vet/race/advisory, cross-build and offline export passed; native capability skips on host remain skips. Raw logs remain private with shared hashes. These binaries were host cross-built: no native source-build claim is made for the new 114-case candidate, and earlier native-built ninety-case evidence retains its original scope.

Issue #84 tracks this bounded outcome for review under still-open #17. In-memory constructed requests do not test relayd wire parsing; cookie strings are provided directly to middleware. Upstream CRS regression, realistic false-positive tuning, response phases, compression/streaming/resource behavior, trust/TLS and appliance adoption remain open. Original failed contracts, source-build timeout and historical 59/63 traffic/polling-window observations remain unchanged. Evidence/docs commits reuse these runtime hashes and do not claim another native run.
