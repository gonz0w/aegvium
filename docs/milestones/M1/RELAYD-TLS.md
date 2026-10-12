# Bounded stock TCP relay TLS termination

Status: authorized research; no supported TLS or connector policy adopted.

## PRD

RL-01: retain all fifty-three existing expectations. Add a guest-loopback TLS listener on port 18083 using stock TCP relayd, forwarding plaintext only to the same local inspection target. Add four normal benign/denial cases, two ordinary pipeline cases, inspection-loss/recovery and two strict client certificate rejection cases. Connected admission becomes sixty-three leaves.

RL-02: generate a fresh synthetic RSA key/certificate only inside the owned guest, keep the private key root-only, and remove every TLS artifact on exit. Bind the public certificate hash to both daemon setup and fixture receipts. Never transfer, publish or retain the private key outside the disposable guest.

## EDD

The [OpenBSD 7.9 manual](https://man.openbsd.org/OpenBSD-7.9/relayd.conf.5) documents TLS listeners and protocol keypair names. Append a distinct TCP/TLS protocol and relay; preserve both plaintext profiles. Use base openssl and a fixed synthetic request configuration with DNS SAN fixture.test, SHA-256 signing, a one-day certificate and RSA 2048. The fixture keypair name is unique to the owned guest. Require absence before generation, register cleanup before generating anything, set umask 077/private-key mode 0600 and make only the public certificate readable by the nonroot fixture. Record its SHA-256, never key contents or hash.

The Go client trusts only that synthetic public certificate, verifies fixture.test and requires TLS 1.2 or later; no InsecureSkipVerify. HTTP/1.1 only, no ALPN feature adoption. Raw TLS pipeline connections use the same strict configuration and six-second deadline, and retain handshake version/cipher/verified-chain observations. The inspection listener stays plaintext loopback. Certificate rejection leaves use an empty trust store or wrong expected name and require the specific Go x509 error type, zero backend receipts and zero application arrivals. These test client verification, not relayd rejection of unknown SNI or Host.

Add TLS readiness to the existing bounded readiness polling. During inspection loss, require only error/transport failure responses with zero backend forwards; after parent-owned inspection restarts, TLS recovery must preserve exactly one benign POST receipt/body. Preserve all existing timeouts, failure expectations, capture caps and synthetic rules. TLS health checks still probe inspection directly over HTTP; no backend fallback or network/PF/service changes.

## Test Design and rollback

Require all sixty-three named leaves and public-certificate/cleanup receipts; reject missing/failed/skipped cases and mismatched certificate fingerprints. Host connected skip remains a skip, and twenty native engine cases stay separate. Run local verification, Go tests/vet/race/cross-build/advisory review before a signed clean native repeat. Keep patched/rebooted owned guest, nonroot fixture, daemon/listener/socket cleanup, VM teardown and unchanged source/base gates. Extend absence checks to the TLS port and owned TLS files, including failures before daemon startup.

This is a small synthetic HTTPS path, not TLS policy hardening, client identity, server-side unknown Host/SNI default denial, certificate renewal, backend TLS, broad parser/CRS coverage or appliance adoption. Retain every failure; remove artifacts and dispose of the owned guest.

## Observed native result

[Retained receipts](../../../research/relayd/tls-observations.json) identify signed runtime candidate `c16ba111bbb6335834da96b7ac5064df25c0016e`, tree `0895d9a7243abad6913fbd7c946e0b09b1c0c6b1`, and owned run `3022f72e-54d7-43c4-8ea4-b981f1bc27a7`. All ten added TLS leaves passed. The full connected suite remains **failed at 59/63** on the same four ordinary/long-idle HTTP pipeline expectations; no failure or admission requirement was removed.

Stock relayd accepted the TLS profile and terminated both pipeline connections using TLS 1.3 (`0x0304`), cipher `0x1302`, one verified certificate chain and no negotiated ALPN. Denied/benign returned 403/200 with exactly one backend receipt; benign/benign returned 200/200 with exactly two. Their complete plaintext inspection streams matched the client request hashes and lengths (111 and 109 bytes), with zero hostile URI receipts and no capture overflow. These two samples demonstrate useful stock TCP/TLS dispatch without the HTTP reader's tested pipeline failure; they do not prove universal byte preservation or establish the installed binary's source/build lineage.

Benign GET/POST and URI/body denial passed the bounded TLS assertions. An empty trust store and incorrect expected name produced the required client x509 errors, zero backend receipts and zero application arrivals. This is client verification evidence only: no server-side unknown SNI/Host rejection was asserted. With inspection closed and the backend alive, all three TLS attempts produced transport errors and zero backend forwards; TCP did likewise. HTTP returned 500/502/502. Restoring inspection admitted exactly one expected TLS POST receipt/body, alongside the unchanged direct/HTTP/TCP recovery controls.

The setup and Go fixture public-certificate fingerprints matched (`9717909bf780f416c6c4ef8341394ae012359e264e780cb463831ca71210df41`). The guest verified private-key mode 0600 and artifact absence on cleanup; no private key was transferred or published. Cleanup receipts verify removal of the owned key, certificate and request configuration, foreground daemon, listeners and control socket. VM teardown and unchanged source/base checks passed. File removal is not a secure-erasure claim.

All twenty separate native engine cases and historical syntax controls passed. The guest authenticated all 34 reviewed patches, reported zero pending patches and rebooted before testing. Local verification passed 43 checks; host Go tests passed twenty engine leaves and two recorder subcases, explicitly skipping connected execution. Vet, race, OpenBSD cross-build and advisory review passed. The native fixture executed a host cross-built binary, not a fresh native source build. Published runtime input fingerprints match the tested signed candidate; later documentation/receipts do not represent another execution.

## Remaining gates

TLS termination through stock TCP relayd is a bounded research candidate. Trusted client identity, direct-access prevention, server-side Host/SNI default denial, certificate lifecycle, backend transport policy, response inspection, broader framing/CRS corpora and performance still need separately scoped designs and native evidence. Keep HTTP pipeline failures and earlier diagnostic attempts visible. No reusable connector, supported runtime profile or appliance deployment is adopted here.
