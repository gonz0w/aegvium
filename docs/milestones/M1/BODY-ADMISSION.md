# Bounded body admission research

Status: authorized bounded M1 research under connector/body handling; no runtime adoption.

## PRD

BA-01 (M1-02/03, WAF-03/04): compare pinned On-mode CRS middleware with a test-only body admission gate. Require preserved admitted bytes, retained attack denial, explicit bounded size/media/encoding/read-error rejection and zero backend receipts on gate failures. Baseline outcomes are characterization, not acceptance of implicit success or an appliance body policy.

## EDD

BA-02: fixed research cap 128 bytes, deliberately not an appliance limit. Admit only one well-formed JSON/form Content-Type with optional UTF-8 charset, and no Content-Encoding or one identity value. Reject unsupported/ambiguous media/encoding with 415. Reject declared size over cap before reading; independently read at most cap+1 for accepted headers so unknown or understated length cannot evade the cap. Over-cap bytes return 413; read errors return generic 500; a nonnegative declared length differing from consumed bytes returns 400. Close the consumed original source once within this constructed-request gate, replace successful input with a bounded memory reader and preserve original middleware's attack/body-processor rejection. No JSON parser, decompression, temporary files or new dependencies are introduced.

This is a research wrapper in a test file, not a companion proxy or selected route policy. Reads rely on the enclosing transport for timeouts; a byte cap does not bound stalled I/O or concurrent memory use. Closing a body does not prove closing a network connection. Transport/server cleanup ownership, wire framing and supported body profiles require separate native HTTP design.

## Test Design

BA-03: thirteen cases, each baseline/gated: benign form/JSON, form SQL/JSON script denial, exact-cap JSON, declared/unknown/understated over-cap JSON, malformed JSON, text media, advertised gzip and immediate/partial failing readers. Use fresh WAFs with pinned existing rules and no rule threshold/exclusion overrides. Record status/backend, actual original-source bytes read/close count and matched IDs/phases; assert admitted body preservation. Baseline observations are source-bound independently. Gate failures must return explicit status with no backend and no more than 129 source bytes; successful or rejected gate ownership must close its original once in this constructed fixture. Eight additional gate controls cover UTF-8/identity acceptance, duplicate/malformed media, unsupported charset, duplicate encoding and short/long declared length. Original middleware's known implicit-200/no-backend read-error characterization remains retained, not repaired silently.

BA-04: add strict result admission and mutation checks, export the new file and execute all prior 114 leaves plus thirty-four new leaves (twenty-six paired matrix and eight header/length controls) on disposable OpenBSD. Host test/vet/race/advisory/cross-build/export and make verify are tooling evidence. Retain signed source/tree, pinned rule hashes, native nonroot/patch/reboot/bootstrap/source/base/teardown and failures. Keep host and native observations comparable without claiming socket behavior from httptest.

## Compatibility and rollback

Remove the research gate/test/export/admission entries to roll back; retain observations and prior failures. JSON/form policy, size cap and generic error classification remain proposed research choices. No live services, relayd profile, installer schema, response inspection, full CRS or OWASP coverage change. Earlier cross-built/native-built results retain their original case counts and sources.

## Native result

[Source-bound observations](../../../research/native/body-admission-observations.json) bind signed runtime candidate `57cc4181d78afccde33017f426d623b1050d4b2f`, tree `b221d85a8e84d260843025e1e6f0c47de16e10aa`, owned run `73fb7474-0753-40c5-819c-ea161302bb4c`. All 148 ordinary native leaves passed as UID 32767: prior 114 unchanged, thirteen paired baseline/gated cases and eight header/length controls. Exact status/backend/read/close-call/rule-ID/phase observations matched the host matrix. The prior twenty-four CRS corpus observations and all 51 pinned bundle-file hashes were unchanged.

The gate admitted three benign/exact-cap inputs with preserved bodies and retained three inherited attack/malformed-JSON denials. Seven gate failures returned explicit 413/415/500 with zero backend receipts. Declared oversize, text media and advertised gzip were rejected without reading source bytes. Unknown/understated oversize inputs read exactly 129 bytes before 413. Immediate/partial read failures returned 500 without backend access; the partial source delivered sixteen bytes with its error. The baseline middleware retained its two implicit-200/no-backend reader-error observations. All thirteen gated matrix sources received one Close invocation, and the eight header controls independently checked ownership. Baseline sources were closed by fixture cleanup after observation; these counters do not prove network or descriptor teardown.

Malformed JSON returns 400 from recommended rule 200002, and the advertised gzip sample returns baseline 403 from 920450/949110. The first uncommitted host characterization had provisional status expectations wrong for those cases. Its failed log and exact source digest/content remain retained without signed-source attribution. Source-confirmed rejection statuses were corrected; no gate rejection or backend-zero condition was weakened. The gzip header accompanies plain synthetic JSON, so no actual compressed-byte processing was qualified.

Authenticated 34 patches/zero pending/reboot, bootstrap rejection, source/base invariance and owned VM teardown passed without escalation. Sixty-seven curated runtime fingerprints match the signed candidate/current files. Fifty-three local checks, host test/vet/race/advisory, cross-build and offline export passed. This is native execution of a host cross-build, not a new native source build. Raw logs/private initial source remain local with shared hashes; evidence/docs commits reuse the exact runtime inputs and do not claim another native run.

Issue #86 tracks this bounded outcome for review; #84 is Done following merged #85. The 128-byte cap, media/error choices and constructed-request ownership remain research policy. Stalled I/O, concurrency/peak memory, Close-return errors, real HTTP framing/server drainage, transport lifecycle and route policy remain unqualified. No live service, relayd profile, installer or appliance adoption changed. Historical failures and native/cross-built results retain their original scopes.
