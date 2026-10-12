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
