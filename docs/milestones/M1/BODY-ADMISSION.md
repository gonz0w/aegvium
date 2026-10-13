# Bounded body admission research

Status: authorized bounded M1 research under connector/body handling; no runtime adoption.

## PRD

BA-01 (M1-02/03, WAF-03/04): compare pinned On-mode CRS middleware with a test-only body admission gate. Require preserved admitted bytes, retained attack denial, explicit bounded size/media/encoding/read-error rejection and zero backend receipts on gate failures. Baseline outcomes are characterization, not acceptance of implicit success or unlimited application policy.

## EDD

BA-02: fixed research cap 128 bytes, deliberately not an appliance limit. Admit only one well-formed JSON/form Content-Type with optional UTF-8 charset, and no Content-Encoding or one identity value. Reject unsupported/ambiguous media/encoding with 415. Reject declared size over cap before reading; independently read at most cap+1 for accepted headers so unknown or understated length cannot evade the cap. Over-cap bytes return 413; read errors return generic 500; a nonnegative declared length differing from consumed bytes returns 400. Close the consumed original source once within this constructed-request gate, replace successful input with a bounded memory reader and preserve original middleware's attack/body-processor rejection. No JSON parser, decompression, temporary files or new dependencies are introduced.

This is a research wrapper in a test file, not a companion proxy or selected route policy. Reads rely on the enclosing transport for timeouts; a byte cap does not bound stalled I/O or concurrent memory use. Closing a body does not prove closing a network connection. Transport/server cleanup ownership, wire framing and supported body profiles require separate native HTTP design.

## Test Design

BA-03: thirteen cases, each baseline/gated: benign form/JSON, form SQL/JSON script denial, exact-cap JSON, declared/unknown/understated over-cap JSON, malformed JSON, text media, advertised gzip and immediate/partial failing readers. Use fresh WAFs with pinned existing rules and no rule threshold/exclusion overrides. Record status/backend, actual original-source bytes read/close count and matched IDs/phases; assert admitted body preservation. Baseline observations are source-bound independently. Gate failures must return explicit status with no backend and no more than 129 source bytes; successful or rejected gate ownership must close its original once in this constructed fixture. Eight additional gate controls cover UTF-8/identity acceptance, duplicate/malformed media, unsupported charset, duplicate encoding and short/long declared length. Original middleware's known implicit-200/no-backend read-error characterization remains retained, not repaired silently.

BA-04: add strict result admission and mutation checks, export the new file and execute all prior 114 leaves plus thirty-four new leaves (twenty-six paired matrix and eight header/length controls) on disposable OpenBSD. Host test/vet/race/advisory/cross-build/export and make verify are tooling evidence. Retain signed source/tree, pinned rule hashes, native nonroot/patch/reboot/bootstrap/source/base/teardown and failures. Keep host and native observations comparable without claiming socket behavior from httptest.

## Compatibility and rollback

Remove the research gate/test/export/admission entries to roll back; retain observations and prior failures. JSON/form policy, size cap and generic error classification remain proposed research choices. No live services, relayd profile, installer schema, response inspection, full CRS or OWASP coverage change. Earlier cross-built/native-built results retain their original case counts and sources.
