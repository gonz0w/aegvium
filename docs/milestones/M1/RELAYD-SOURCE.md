# Bounded relayd release-source attribution

Status: completed static research under the 2026-10-11 authorization. Installed binary attribution and repair remain open.

## PRD

RS-01: replace date-based development-history guesses with authenticated official OpenBSD 7.9 release source. Pin archive, signed manifest, release key and exact HTTP source hashes. Keep official release lineage distinct from the third-party laboratory image's installed binary.

RS-02: compare the buffered-header callback condition with the discovery snapshot without changing relayd, expectations or ingress policy. Preserve the failed 30/34 native result and identify remaining repair gates.

## EDD and Test Design

Download only the official release archive, signed checksum manifest and public release key into ignored host storage. Match the public key with the independently published [release page](https://www.openbsd.org/79.html). Decode the Ed signify record, require matching algorithm/key IDs, construct an Ed25519 SubjectPublicKeyInfo and use existing host OpenSSL to verify the exact signed message. The message consists of all bytes after the manifest's two framing lines, including original newlines. Require successful verification and rejection after changing one message byte. Match the complete archive SHA-256 to the authenticated entry before reading the named source member with Python tarfile; do not unpack the archive into the workspace or execute its contents.

This is host verification tooling, not a native signify receipt or new runtime dependency. No source rebuild, native execution, source patch, copied upstream code, service or installer changes belong to this slice. Upstream's ISC-style permission notice remains in the ignored unmodified member.

## Observations

[Machine-readable fingerprints](../../../research/relayd/release-source.json) retain exact URLs, sizes, hashes, key anchor, verifier and actual outcomes. The 204,451,355-byte archive matches authenticated SHA-256 `fb305c553059b48e8ee64539f392b783cb38a67865823f6f6a94f3b220a1268b`. OpenSSL 3.6.3 accepted the original message (exit 0) and rejected the one-byte modification (exit 1). The public key exactly matches the release page; trust here depends on that HTTPS anchor.

The release member is `usr.sbin/relayd/relay_http.c`, RCS revision 1.96 dated 2026-04-02, 54,232 bytes, SHA-256 `bef2d0040c176a3ffc867b8f48d8566f090ecbf3ca1113a8559e2514cb1bc744`. This differs from the revision 1.107 October discovery source, so the earlier snapshot must not be described as release source.

In the authenticated release member, the header loop ends a header section (lines 214–237), bodyless GET selects zero remaining body bytes (490–497), and the tail re-enables reading but excludes the HTTP header reader from the immediate pending-input callback (598–602). The body reader transitions back to header reading and invokes the changed callback (647–660). Thus the candidate mechanism exists in official release source as well as the newer discovery snapshot. This static inference remains consistent with the [four successful wake controls](RELAYD-BUFFER.md); it does not prove where bytes waited in the installed daemon.

For reproduction, fetch the pinned URLs and require the receipt's hashes. Base64-decode the second key/manifest lines; both records begin with a two-byte algorithm and eight-byte key identifier. Strip those ten bytes to obtain the 32-byte key and 64-byte signature. Prefix the key with DER hex `302a300506032b6570032100`; verify using:

```sh
openssl pkeyutl -verify -pubin -keyform DER -inkey release-ed25519.der \
    -rawin -in release-manifest.txt -sigfile release-signature.bin
```

Do not treat a checksum from an unauthenticated manifest, a release date or a nearby Git commit as release attribution. No upstream implementation excerpt is redistributed here.

## Remaining gates and rollback

The laboratory's installed daemon hash remains independently recorded; official release source authentication does not establish its compiler, build flags, applied source changes or original image provenance. A native release-source build and controlled comparison would add distinct evidence, not retroactively qualify the image. A repair needs a scoped reviewed design addressing buffered-header progress, recursion/use-after-free, backpressure, incomplete headers, bodies/chunks and response/connection lifecycle, with original failing cases retained. A stock transport-only relayd comparison remains another bounded option.

No supported ingress profile, patch or connector adoption follows from these results. Historical failures, TLS/client identity, broad parser and CRS gates remain open. Rollback consists of discarding ignored downloads; runtime and native fixtures are unchanged.
