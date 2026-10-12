# Bounded PROXY v1 parser research

Status: authorized research; no listener, trusted sender or connector policy adopted.

## PRD

RP-01: parse a mandatory PROXY v1 TCP4 prefix with a 56-byte maximum including CRLF. Require canonical IPv4 endpoints, decimal nonzero ports no greater than 65535 and an exact expected destination. Return no usable identity on failure.

RP-02: preserve buffered HTTP bytes after one prefix, including coalesced and fragmented input and multiple requests. Execute four accepted cases, twenty rejected cases and one injected reader-error case on the host and in the owned OpenBSD guest. Preserve the existing twenty engine cases and all historical connected results.

## EDD

Use only Go standard library in the isolated research module. A private parser takes a bufio.Reader and expected IPv4 destination, reads at most 56 bytes one at a time and stops at LF. Require CRLF, six fields separated by single ASCII spaces, literal PROXY/TCP4, canonical netip IPv4 addresses and canonical decimal ports in 1–65535. Zero ports are intentionally outside this narrow profile, although the general protocol permits them. UNKNOWN, IPv6, v2 and autodetection are unsupported and rejected. A returned value contains only parsed source/destination; it carries no authentication assertion.

Retain the same reader after parsing so read-ahead belongs to the HTTP consumer. No socket, Accept wrapper, HTTP handler, deadline enforcement, Coraza REMOTE_ADDR mapping or forwarding-header change is implemented here. A future socket adapter must set a concrete read deadline before invoking this parser, clear or replace it safely afterward, and contain unauthorized peers before trusting any identity. This parser's byte bound does not prevent a blocking reader from waiting forever. Readiness separation, Host/SNI, immutable connection context and local sender containment remain the prerequisites described in the [identity study](RELAYD-IDENTITY.md).

## Test Design

Accepted leaves: coalesced prefix/application data, one-byte fragmented input, two pipelined request bytes and maximum-length IPv4 prefix. Assert exact source/destination and exact remaining byte stream. Rejected leaves: missing prefix, truncation, overlong prefix, bare LF, wrong magic, wrong family, UNKNOWN, v2, invalid source/destination, leading-zero address, mapped IPv6, zero/overflow/leading-zero/signed port, duplicate space, tab, extra field and wrong destination. Every rejection must return an error and zero identity; a counting reader verifies parser consumption never exceeds 56 bytes. Inject a non-EOF read error after a partial prefix and require errors.Is preservation with zero identity.

Host tests are tooling evidence. The native controller must require all 45 leaves (20 unchanged engine plus 25 parser) without skips/failures, nonroot UID, signed clean candidate, authenticated patches/reboot, bootstrap rejection, unchanged source/base and owned VM teardown. Host admission tests must reject a missing parser leaf. Connected admission stays 63; this slice does not repeat or replace its failed 59/63 evidence. Compile on the pinned host Go toolchain and cross-build for native execution; do not claim a new native source build.

## Compatibility and rollback

The parser is a deliberately restricted experiment, not a complete PROXY implementation or authenticated connector. Native in-memory execution cannot establish stock relayd wire output, socket timing, trusted identity, bypass prevention, header sanitization or readiness. No dependency, listener, service, network/PF or installer change. Rollback removes the parser experiment and its admission extension; retain original observations.
