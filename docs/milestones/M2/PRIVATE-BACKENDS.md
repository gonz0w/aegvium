# Inspector-private backend startup source

This is connected source configuration and trust preparation, not a DATA receiver,
application attempt, authentication result or positive runtime profile. It changes
neither AGPAIR1, M2-H1/1 nor AGCHECK104. All operational entry/validation holds stay.

The existing root/operator trust owns fixed inputs under `/etc/aegvium/inspector`.
Actual source startup uses its existing protected-directory, root:dedicated-GID0440,
regular/nlink1/no-follow, cap+1/double-read/current-metadata and once-Close path.
It loads the private configuration and material before the prepared diagnostic.
Private TLS state stays inside the startup owner with no getter, callback provider,
supplied permission or transferable allow record. Bad or partial startup burns its
attempt and remains owned. No credential constructor ran in the pure tests.

## Fixed private configuration

`backend.conf` is at most8192 bytes. Integers are unsigned big-endian and text is
canonical ASCII. The encoding is an internal implementation detail, not a public
configuration language or new provisioning authority:

```text
8 bytes "AGBACK1\n"
32 ASCII bytes of the exact inherited AGPAIR generation
32 raw SHA256 bytes of the complete inherited AGPAIR descriptor
u16 client-role DNS length (1..253), exact client-role DNS
32 raw SHA256 bytes of the configured backend-client root DER
u8 route count (1..8), then sorted entries with exact AGPAIR route-ID coverage:
  u8 route-ID length (1..32), route ID
  u8 IPv4 text length (1..15), canonical numeric IPv4
  u16 backend port (1..65535)
  u16 backend-server DNS length (1..253), exact server DNS
  32 raw SHA256 bytes of that route's backend-server root DER
```

Missing/extra/reordered routes, padding, trailing bytes and stale generation or
digest refuse. IPv6, discovery, URLs and request-selected destinations are absent.
Static address checks exclude unspecified/multicast and limited broadcast; they
cannot prove whether an address is a directed broadcast without network context.
This format supplies no network-isolation attestation. Backend-client DNS cannot
be a frontend, inspector-server, public-endpoint or configured backend-server role.
Each route retains its own fixed endpoint, DNS identity and anchor; repeated
backend-server names across routes do not merge destinations or trust.

Fixed files are `backend.conf`8192, `backend-cert.pem`65536,
`backend-key.pem`16384, `backend-client-root.der`16384 and one
`backend-<lowercase root SHA256>.der`16384 per distinct server anchor (at most8).
These join the existing role files: at most23 files total. The fresh builder
copies only protected operator inputs into its private media and the placement
helper validates exact coverage/anchor bytes before exclusive protected writes,
readback and file/directory sync. The original five-file payload is unchanged.
Actual provisioning and every private media/image/account operation remain held.

## TLS preparation and remaining lifetime

The actual source constructor validates the client chain/time, exact literal DNS
SAN and sole ClientAuth EKU against its separately configured pinned root. Parsed
client public-key/SPKI equality with the actual inspector-server leaf is refused;
different certificate wrappers cannot hide key reuse. All client DNS SANs remain
disjoint from other configured roles. Public frontend keys are never inputs here;
their custody/provisioning still requires its own real owner and acceptance.

Each private route owns a fresh TLS1.3/`http/1.1` configuration with only its explicit
server root, fixed server name and owned client certificate. No ambient roots,
verification bypass or session cache/resumption is selected. Its future handshake
callback checks exact literal server DNS, sole ServerAuth EKU, exact verified-chain
anchor, current chain/client validity and role conflicts. Constructing this state
is not proof of any connection, authenticated request or backend permission.

There is no listener, dial, request writer, backend-attempt caller or Ready path in
this slice. Real serving must keep the actual same-connection admitted request,
one C02 lease and the same Coraza transaction through the sole backend exchange
and terminal I/O cleanup, before logging/transaction Close/lease release. Existing
inert engine outcomes cannot be used to trigger that attempt. Framing, actual V
generation/history/HAProxy ownership, backend isolation, native TLS/resources and
the full four-second shutdown gate remain required.

The independent pre-code213-byte opaque configuration literal has SHA256
`5e4c6aec468aa1309aa2e7bf470637ce7b9860f333d484fc1d4af481b5e1aa5e`.
Pure tests use this public descriptor/configuration and intercepted builder I/O;
they never parse credentials, perform TLS or connect to an application.

## Common endpoint source binding

The [approved AGPAIR2 source successor](AGPAIR2.md) now binds explicit CONTROL
and DATA endpoints with H1/3; the current source parses/prepares it without
serving. AGPAIR1 remains unchanged and CONTROL-only; DATA cannot infer another
port or share that control listener. Both versions preserve the fixed control
HTTP path, AGCHECK104 semantics, server role/trust, fresh generation, complete
digest and8192-byte cap. Private AGBACK1 still binds exact full descriptor bytes,
so an endpoint/profile change requires an explicitly matching private input.
No actual listener, credential, TLS or native operation is enabled by this source.
