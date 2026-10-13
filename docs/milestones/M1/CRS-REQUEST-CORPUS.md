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
