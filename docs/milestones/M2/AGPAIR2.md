# AGPAIR2 and strict connection facts

Source direction approved on 2026-10-22; operational entrypoints remain refused.
This extends the [legacy control contract](OWNED-PAIR-RECEIVER.md) and
[H1/1 context](FRONTEND-INSPECTOR-CONTRACT.md) for coordinated Vectivium source
integration. The [joint freeze](AGPAIR2-FREEZE.json) binds the public synthetic
literal bytes. No TLS, credential, socket, image or native acceptance is claimed.

## Complete descriptor and control binding

All integers are unsigned big-endian. Text uses the legacy canonical grammar,
route/peer ordering and uniqueness. No padding, optional or trailing bytes:

```text
"AGPAIR2\n"[8], G[32 lowercase hex], "M2-H1/3"[7], u8 routes(1..8)
for each sorted route:
  u8 ID length, ID[1..32]
  u16 public DNS length, DNS[1..253], u16 public port(1..65535)
  policy pin[64 lowercase hex]
  u8 frontend peers(1..8), each sorted: u16 DNS length, DNS[1..253]
  u8 CONTROL IP length, canonical numeric IP[1..45], u16 CONTROL port
  u8 DATA IP length, canonical numeric IP[1..45], u16 DATA port
  u16 inspector DNS length, DNS[1..253]
  inspector-server root DER SHA256[32], frontend-client root DER SHA256[32]
u32 limits:4096,5120,2048,4096,4096; u8 requests4,data sockets8; EOF
```

Both ports are nonzero. Preserve numeric-address exclusions: no unspecified,
multicast, limited IPv4 broadcast, zone or mapped IPv6. CONTROL and DATA tuples
must differ. Equal ports on distinct addresses are permitted. All production
routes bind identical CONTROL/DATA tuples, inspector role and both anchor pins;
the selected frontend role must be allowed by each route it uses. Structural
parsing is detached data, never listener or caller authority. The complete
descriptor remains at most8192 bytes; an added endpoint consumes that capacity.

AGPAIR1/M2-H1/1 remains byte-identical and CONTROL-only. It has no DATA projection.
AGPAIR1/P3, AGPAIR2/P1, P2 and unknown combinations refuse, without negotiation.
The fixed control path stays `POST /_aegvium/m2-h1-1/pair`: it names the control
protocol, not a wire-selected application capability. Close-only HTTP/1.1,
existing authentication, two control slots and original clocks remain unchanged.

`D=SHA256(ALL descriptor bytes)` includes both endpoints. `C=SHA256(P)` comes
from the validated local descriptor. Q remains `AGCHECK1[8] || G[32] || D[32] ||
C[32]`, exactly104 bytes. DATA-only edits alter D/Q without selecting a different
CONTROL destination. Equality reports prepared bytes only, never frontend
acceptance, Ready or backend authority. The inherited AGBOOT frame and payload
builder retain the complete descriptor and tuple without expanding their caps.
Private AGBACK1 must be rebound to the new full D before preparation succeeds.

The single durable consumed-generation namespace remains continuous across C1
and C3. No new profile namespace, reset, deletion or reuse is permitted. Existing
startup uncertainty burns the generation; source tests prove no physical custody
or rollback-free storage. The Vectivium history owner separately preserves old
C1 inventory while recognizing current C3 records.

## H1/3 public connection observations

There are six context fields: Contract, Route, Generation, Request, SNI and
Connection, under the existing `Aegvium-` prefix. Connection replaces Client;
old aliases, extra reserved names, duplicate/missing fields and profile mismatch
refuse. It is exactly `remote-ipv4:remote-port/local-ipv4:local-port`, canonical
dotted decimal IPv4 and decimal ports1..65535 without leading zeros, at most43
bytes. No whitespace, list, bracket, hostname, IPv6 or suffix is admitted.

Both tuples must come from the same actual accepted PUBLIC connection before
rewrite, together with its actual public SNI and complete request. Never derive
them from Host, route, internal hop, backend, PROXY/Forwarded, dummy values or
pre-NAT guesses. TLS authenticates the frontend observation claim; it does not
make Aegvium an independent observer of the public socket. Actual public local
port remains separate from route authority port. Map remote to engine client
AddrPort and local to engine server AddrPort under the same owned job.

All reserved fields are stripped before application forwarding; no new response,
log, metric, persistence or recipient is introduced. The engine already requires
these four facts. Six context fields preserve58 application slots within64 total.
Maximum canonical context grows514→546 bytes, within1024; with4096 public bytes,
the total4642 remains below5120. Copied tuple/storage allocations still require
actual resource qualification; syntax/byte arithmetic is not a memory proof.

## Source checks and remaining workflow

Pure literal tests cover old/new byte binding, every truncation, incompatible
versions, endpoint independence, cross-route mismatches, bootstrap Q equality,
payload retention, private full-D binding and canonical connection rejection.
The actual C storage source is exercised only with every subject OS operation
intercepted. No credential/TLS/engine constructor or native product path runs.

The parsed context remains a DTO with no production Peer issuer. Real DATA
requires the same verified connection/body and shared job lease through actual
inspection, the sole backend attempt, terminal exchange/logging/transaction Close
and join before release. No transferable allow record is introduced. Actual
frontend observations, strict original-wire rejection, listener containment,
private-role custody, resource limits and four-second shutdown remain required
and unqualified. Default operational refusal and Draft126's pause remain.
