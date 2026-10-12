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
