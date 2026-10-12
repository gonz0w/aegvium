# Bounded stock TCP relay control

Status: authorized research; no supported profile or connector adoption.

## PRD

RT-01: retain all thirty-four existing direct/HTTP-relay expectations. Add a stock TCP relay on guest loopback port 18082 forwarding only to inspection port 18081, using the same HTTP readiness check. Compare four normal benign/denial cases and seven existing raw framing/reuse cases without extra wake input; require the same statuses and exact backend receipt assertions.

RT-02: add separate TCP inspection-loss and recovery leaves, expanding connected admission to forty-seven cases. Preserve existing HTTP pipeline failures rather than dropping that arm or treating a successful TCP arm as overall qualification.

## EDD

The [7.9 manual](https://man.openbsd.org/OpenBSD-7.9/relayd.conf.5) documents TCP protocols and HTTP target checks. Append a TCP protocol/relay to the foreground-only traffic fixture; preserve the existing HTTP block exactly. Both listeners dispatch only to the same inspection table. No TLS, PF, rc.d, upstream source patch or new dependency is introduced. The syntax-only historical fixture stays separate.

Run the TCP raw arm before changing the inspection idle timeout, using the same one-second profile, six-second exchange deadline, stream recorder, byte/event caps and synthetic backend. Skip diagnostic wake leaves for the new arm; its ordinary pipelines must work without a stimulus. Readiness must succeed through both ingress listeners and never reach the backend. During loss the synthetic backend remains alive, both ingress arms must produce only transport failure or error responses and zero backend forwards; recovery requires one exact benign POST receipt per arm.

Health selection remains useful, but transport-only forwarding supplies no HTTP header routing/filtering or trusted client identity. Client identity, TLS termination and the planned relayd-based proxy's routing contract require distinct designs. Plaintext TCP comparison cannot qualify those features.

## Test Design and rollback

Current admission must require all forty-seven named leaves and reject omission/failure/skip. Native execution requires signed clean source, patched/rebooted owned guest, nonroot fixture, syntax acceptance, daemon/listener/control-socket cleanup, owned VM teardown and unchanged source/base. Cleanup checks include all three fixture ports. Host connected skip remains a skip; twenty native engine cases remain separate.

Run local repository and research checks before native execution. Preserve actual statuses, stream observations, receipt counts and failures. No measured result or safe profile is assumed in advance. Dispose of the owned guest; no live service or network changes.

## Initial syntax failure

Candidate `b89d9b1c461da9d7db00894b1fd8dc9118163109`, owned run `1e62de40-2665-4067-963f-d8713d13df30`, failed traffic syntax validation at the empty TCP protocol block. The release parser accepts an empty block only without the intervening newline. The foreground daemon was never started and zero connected cases ran; no traffic cleanup receipt exists for this pre-start failure. Separate twenty engine cases and historical syntax tests passed. Authenticated patches/reboot, bootstrap rejection, owned VM teardown and source/base invariance passed. Correct the block to inline empty braces and repeat in a fresh owned guest; retain this attempt rather than describing it as traffic evidence.

## Native comparison result

Corrected candidate `544f8181469509b692917b2db1a415ed3dddc40c` ran as UID 32767 in fresh owned run `988cdb86-e60a-436b-b65b-87eeee839192`. Native syntax acceptance succeeded and all forty-seven connected leaves executed. The run **failed at 42/47**: four original HTTP-relay pipeline failures remained, and the new TCP recovery POST failed. [Receipts](../../../research/relayd/tcp-observations.json) retain both attempts, exact inputs/log/report hashes, named outcomes and bounded stream observations.

Twelve of thirteen new TCP leaves passed. Both ordinary pipelines worked without wake input: denied/benign returned 403/200 with exactly one benign backend receipt; benign/benign returned 200/200 with exactly two. Inspection consumed the full 111-/109-byte client streams with matching hashes and two application arrivals. This is evidence for those synthetic streams, not general protocol or byte-preservation qualification. TCP serialized reuse passed as well.

TCP benign GET/POST preserved expected receipts/body bytes; URI/body denial and chunked attack forwarded nothing. Chunked benign had one exact receipt. Conflicting Content-Length returned 400 with zero backend receipts; mixed framing attack returned 403 with zero. All thirty-one raw snapshots recorded zero hostile URI receipts and no capture overflow. Failed HTTP baseline counts remain observations rather than successful assertions.

With inspection closed and the backend alive, TCP attempts produced three transport errors and zero backend forwards; HTTP attempts returned 500/500/502 and zero forwards. After restart, readiness HEAD succeeded through both listeners and the HTTP recovery POST passed. The immediately following TCP recovery POST returned EOF (status 0), empty response and zero backend receipts. Thus readiness success did not establish successful next-request recovery in this sample. Aggregate daemon health down/up transitions do not attribute that failure to a particular connection. Do not retry until success inside the test or weaken its assertion; diagnose recovery separately.

Separate twenty native engine cases and historical configtests passed. Bootstrap rejection, authenticated patches/reboot, daemon/listener/control-socket cleanup, owned VM teardown and unchanged source/base verified. Native execution used a host cross-build; no fresh native compile occurred.

This comparison makes transport-only relayd a useful research candidate for pipelining while exposing a recovery blocker. It selects neither a supported profile nor a source repair. Next work should isolate readiness-to-application recovery behavior with connection/stream/backend observations and fresh controls before pursuing TLS/identity or adopting an ingress contract. Original HTTP failures and official-source versus installed-binary attribution remain open.
