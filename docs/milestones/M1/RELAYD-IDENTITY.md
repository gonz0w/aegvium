# Bounded relayd client-identity feasibility

Status: completed static research under the 2026-10-11 authorization; receiver design proposed, implementation and native trust qualification pending.

## PRD

RI-01: establish whether stock TCP/TLS relayd can transmit connection addresses to a companion without HTTP parsing or client-controlled forwarding headers. Trace authenticated OpenBSD 7.9 release source separately from installed binary attribution.

RI-02: identify the trust, TLS metadata and readiness limitations before introducing a PROXY receiver. Give the next bounded experiment explicit rejection, stream-preservation and recovery criteria without adopting an appliance policy.

This informs WAF-03/05/06 and issues #15/#16/#21. It does not satisfy their broad acceptance, resolve the four existing HTTP pipeline failures, or select a reusable connector API.

## Evidence and method

[Fingerprints](../../../research/relayd/identity-source.json) pin five members of the previously [authenticated release archive](RELAYD-SOURCE.md). Recomputed archive SHA-256 matches the signed release entry; existing host OpenSSL accepted the exact signed manifest and rejected its one-byte modification again. Release key/manifest anchoring is inherited from that study, not a new independent trust root. Named members were read with Python tarfile into ignored storage without executing or redistributing upstream implementation. ISC-style notices were inspected; no dependency was added.

The [OpenBSD 7.9 manual](https://man.openbsd.org/OpenBSD-7.9/relayd.conf.5) documents v1/v2 output on a forward directive. In the pinned source, parse.y selects its flags (1107–1109, 1955–1969), relay.c records accepted peer/local addresses (1124–1125, 1172–1186), and the connected output path writes the selected prefix before pending application bytes (774–792). proxy_protocol.c emits v1 TCP4/TCP6 or v2 address blocks; its v2 writer has no TLS, SNI or ALPN TLV construction (55–144). This supports a stock address-transport candidate, not an observed native wire format or installed-source attribution.

The [primary PROXY specification](https://www.haproxy.org/download/3.0/doc/proxy-protocol.txt) defines a per-connection prefix, requires a dedicated receiver mode and trusted senders, and warns against combining different clients on one advertised connection. It carries assertions rather than cryptographic proof. Its HTTPS download is content-pinned separately from the signed OpenBSD archive.

The HTTP status-check parser builds a bare HEAD request (parse.y 917–930); check_tcp.c sends the configured health buffer directly (187–191, 214–237). The inspected path does not call the relay output prefix writer. Therefore the current bare-HTTP readiness probe cannot simply be reused on a listener that requires a PROXY prefix. This static finding needs native confirmation; syntax and observed health behavior must be separate receipts.

## Proposed companion boundary

Start with an isolated, mandatory v1 TCP4 listener in research. Require exactly one complete valid prefix before exposing any HTTP bytes to the inspection server. Use Go standard library tools, a bounded read deadline and maximum prefix size, and preserve any buffered application bytes when handing the connection to net/http. Never guess whether a prefix is present or fall back to plain HTTP. IPv6 and v2 are separate compatibility slices; a strict restricted profile must be labeled accordingly rather than called a complete PROXY implementation.

Store both transport peer and advertised source/destination in immutable connection context. Keep identity stable for every request on that connection. Validate expected destination/listener role independently of HTTP Host. The advertised source is relayd's accepted peer; it is an original internet client only if the upstream network preserves that address. Do not infer EdgeWall NAT behavior from this loopback research.

Strip incoming Forwarded and X-Forwarded-* fields before inspection, then derive any admitted identity fields from the validated connection context. Define whether Coraza REMOTE_ADDR uses the advertised address explicitly and test it independently from backend forwarding. Preserve Host for a separately reviewed route/authority policy; a valid address prefix does not authorize a route. Treat alternate casing, duplicate/comma-separated headers and hop-by-hop nominated forwarding headers as abuse cases.

A TCP/TLS prefix does not provide SNI, negotiated TLS version, client certificate identity or ALPN in the inspected release writer. An HTTPS scheme may be derived from a configured trusted TLS-only listener role after the sender boundary is qualified; it must never come from an incoming X-Forwarded-Proto. Do not assert SNI/Host equality from that role. Unknown SNI handling, certificate selection and HTTP authority denial need their own design and native tests.

Loopback limits remote exposure but does not authenticate relayd. A local untrusted process can fabricate the same prefix, and checking only 127.0.0.1 cannot distinguish it. Keep local sender containment unresolved until a reviewed OpenBSD privilege/PF or authenticated transport design rejects the excluded local peer in an owned guest. No PF rule, user credential or TLS-to-companion contract is invented by this study. The direct inspection/backend controls in the current fixture are intentionally accessible and cannot satisfy no-bypass acceptance.

Readiness must report engine/rules/receiver readiness without creating a plain-HTTP exception on the PROXY data listener. Compare a separately contained readiness endpoint with a deliberately formatted probe in a later design; neither is adopted here. A separate health path must not forward to applications or let a healthy HTTP process conceal a failed identity receiver. A plain TCP connect check alone does not establish inspection readiness.

## Next experiment and Test Design

Before native execution, write and review a bounded receiver/health packet with concrete byte/time limits and a named admission set. Retain all 63 current connected expectations and historical failures. New controls should cover:

| Boundary | Required assertion |
| --- | --- |
| Address transmission | Compare relayd's v1 bytes with the synthetic client's actual local endpoint and relay listener; record transport peer separately. |
| Prefix fragmentation/read-ahead | One-byte and split prefix writes, coalesced prefix plus HTTP, and two requests on one connection preserve application bytes and stable identity. |
| Strict rejection | Missing/truncated/overlong prefix, invalid addresses/ports/separators, wrong family/destination, UNKNOWN and unselected v2 produce zero application/backend arrivals within bounded time. |
| Identity spoofing | Incoming forwarding headers cannot change inspection identity, backend identity fields or trusted scheme; a client-supplied second prefix is never consumed as new identity. |
| Plaintext/TLS dispatch | Native stock TCP and TCP/TLS arms deliver the expected prefix before HTTP; record certificate verification independently. |
| Readiness isolation | Bare HEAD on strict data listener is rejected; admitted health probe never reaches backend; receiver/engine failure removes readiness. |
| Loss/recovery | Engine/receiver loss with backend alive causes zero uninspected forwards; recovery admits exact benign bytes/identity without stale connection state. |
| Local peer containment | An excluded local peer with a valid forged prefix must be rejected by the selected sender boundary. A successful forgery is a retained blocker. |

Only synthetic guest traffic belongs in evidence. No credentials, production addresses, real request headers or raw private inventories. Local parsing tests and cross-builds remain tooling evidence; native wire, privilege, crash/recovery and containment results remain separate. Broader malformed HTTP, IPv6/v2, response phases, CRS, performance and reusable API comparison stay open.

## Recommendation, compatibility and rollback

Stock TCP relayd has a plausible identity transport alongside its observed TLS termination and health-checked dispatch. Prefer a bounded v1 receiver experiment over HTTP header rewriting while the HTTP pipeline failures remain unresolved. This is a research recommendation, not adoption: mandatory prefix handling, readiness separation and local sender containment are prerequisites.

This slice changes documentation/fingerprints only. No native run, receiver, relayd configuration, service or installer change occurred; the previous TLS comparison remains failed at 59/63 with ten new TLS leaves passing. Release-source findings do not prove the installed binary's compiler/build lineage. Rollback is removal of the study and ignored source/spec downloads; historical evidence remains unchanged.
