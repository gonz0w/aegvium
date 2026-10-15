# Bounded TLS passthrough and authority binding

Status: authorized bounded research; native execution pending. Refs #15/#16/#21; no appliance adoption.

## PRD

TP-01: retain stock relayd as a health-checked L4 ingress while the existing guarded companion owns TLS after mandatory PROXY v1. Preserve the existing TLS-at-relayd profile and all its expectations.

TP-02: admit only explicitly configured, certificate-covered `.test` SNI and HTTP/1.1 authority matching that SNI, optionally with the owned ingress port 18120. Reject empty/unknown SNI at handshake, cross-host/wrong-port authority before inspection/backend, bare TLS/plaintext at the prefix listener, and plaintext through relayd. Do not treat PROXY metadata or loopback as sender authentication.

TP-03: preserve pinned CRS, HTTP/verified HTTPS backends, bounded admission and transactional route replacement. Validate all active route names against the startup certificate before binding or replacement; reject incompatible routes while preserving known good service. TLS keys remain ephemeral guest-owned inputs, never evidence. Certificate replacement requires stop/start in this slice.

## EDD

Add an explicit optional certificate/key pair to the owned research CLI. Load bounded regular files and validate the pair before any bind (including check-only). The legacy command remains unchanged. Wrap the existing bounded prefix receiver with Go `tls.NewListener`; net/http sees the actual `tls.Conn` and supplies `Request.TLS`. Prefix read-ahead must remain intact. TLS >=1.2, ALPN HTTP/1.1 only, existing header/read/write deadlines and eight-connection/four-request bounds apply. Handshake uses the current route allowlist and startup certificate; every HTTP request independently checks SNI/authority against its serving route generation. Disable session resumption to avoid bypassing current handshake admission on a resumed connection. Reload updates routes only, with certificate coverage checked before preparation/publication.

Keep TLS-at-relayd as the unchanged control. Run a second daemon profile only after that control is completely stopped. Use the same ports/readiness helper, no PF changes, and no public interface or service enablement. Readiness describes receiver/engine availability, not remote-client certificate success or instantaneous table revocation.

## Test design

Host tests exercise actual prefixed TLS, verified certificates, matched app/api requests, cross-host/wrong-port/unknown/absent SNI, plaintext/missing prefix, slow TLS timeout/recovery, wrong client trust/name, certificate coverage, invalid replacement, activation/removal/rollback and listener closure. Assert exact backend effects and bytes, header stripping and independent cleanup. The disposable OpenBSD run uses the actual guarded executable behind stock TCP relayd, with public-certificate/profile/program hashes and nonroot UID receipts. Admit its exact typed case matrix and startup/reload/cleanup observations; retain failed attempts separately. Repeat unchanged 163 ordinary leaves and 42 legacy path cases, three load phases and seven startup rejects. Native compile fixture/checker/CLI offline; no host fallback.

## Compatibility and rollback

Separate opt-in profile; no dependency version changes. Only close-only HTTP/1.1, IPv4 PROXY v1 and owned loopback addresses are qualified. Stop the owned pair and restore the previous profile to return to TLS-at-relayd; no product configuration migration. Earlier Caddy strict results remain immutable comparison evidence. Certificate distribution/rotation, local sender containment, broader protocols/streaming, hard resource budgets and image/daemon lineage remain adoption gates.
