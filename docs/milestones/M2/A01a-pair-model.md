# A01a-P/1: inert paired-descriptor model

Status: Adopted for scoped source implementation after independent design review
on 2026-10-20. Refs #19/#20/#21. The validation pause remains effective.
Narrow [adapter EDD](ADAPTER-EDD.md) and [Test Design](ADAPTER-TDD.md) to A-PAIR's
in-memory grammar, canonical bytes and equality facts. This does not adopt the
rest of A01a or lift the security/traffic/advisory validation pause.

## Product increment

`internal/pairmodel.Parse([]byte)` validates the exact AGPAIR1 descriptor already
proposed in the adapter EDD. A closed immutable descriptor returns detached
canonical `Bytes()`, the complete-byte SHA-256 digest, and exact `Equal` comparison.
Matching bytes are a structural pairing fact, never readiness, authenticated
identity, generation freshness, an allow token or a backend authorization.

The private grammar, route/peer sorting, string/port/count bounds, two raw trust
digests, fixed five u32 limits and fixed request/socket limits remain exactly as
the EDD. Route IDs follow M2-H1/1's underscore grammar. DNS names use canonical
lowercase ASCII with no trailing dot, wildcard, IP literal or alias repair.
DNS label grammar is the existing M2-C01 grammar: 1..63 lowercase ASCII
letters/digits/hyphens per label, no edge hyphen; one-label names are permitted.
Both public and inspector ports are integers 1..65535. Inspector addresses are
canonical unscoped numeric unicast IP literals; reject unspecified, multicast,
IPv4 limited broadcast and mapped IPv6. Trust-digest bytes are opaque fixed-length
data, not parsed certificates, trust stores or proof of a valid anchor. Require
1..8192 total bytes and reject truncation/trailing bytes, wrong constants,
duplicate/unsorted routes/peers, invalid lengths/characters or numeric ports.
Also reject repeated public DNS/port authorities across route IDs, retaining
M2-C01's structural uniqueness rule. This checks configuration data only.

## Pause and authority boundary

No TLS import/handshake, certificate/key creation/load, receiver/listener, control
operation, network client, engine policy, request-body/traffic fixture, readiness
constructor, history writer or backend call exists in this slice. `requestctx.Peer`
retains private state and no production constructor. Only ordinary format/model
tests with opaque synthetic bytes are permitted here; no security/traffic/advisory
or native validation is performed or relabeled. No changes in Vectivium.

An independent reviewer supplies complete literal descriptor hex/digest golden
vectors from the EDD using a separate Python struct/hashlib oracle before Go
implementation. Include one/two-route, IPv4/IPv6, peer lists and reachable
total-byte boundaries. Go tests check exact byte fidelity, detach, all field
boundaries, truncation at every offset, changed constants and ordering rejection.
Bounded pure parser fuzz/race may follow scoped review; no runtime or effect
claim. Errors remain fixed classifications and never echo descriptor contents.

Real connection-bound mTLS identity, prepared/matched/serving states, consumed
generation history, body/transaction ownership, raw framing and mandatory backend
admission remain unimplemented. Their design/adoption/validation gates and the
existing pause remain effective. This materially advances #20/#21 without closing
either issue or #19. The fixed source-policy bounds are not measured resource
capacity or permission to enable required-WAF.
