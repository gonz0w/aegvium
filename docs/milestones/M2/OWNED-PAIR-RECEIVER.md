# Owned pairing receiver source checkpoint

This private source connects the retained AGPAIR descriptor to an owned request-context snapshot and a receiver-owned `tls.Server` connection. The receiver reads one bounded AGCHECK request from that same connection. It has no public/default provider, listener, serving-ready result, `Peer` constructor, inspection result, allow result or backend forwarding path. The actual transport construction remains behind `aegvium_transport_source`.

## Binding and ownership

The AGPAIR parser is reused unchanged from the retained, clean `codex/pair-descriptor` source at `1a36ee2b7a1976b37b99ed814b79b6d200a17e09`; its `pair.go` SHA256 is `e8d7c003adb0db885b0dc56c93ea9c907cd046d68ce3173c4f37c48d0a7573e7`. A detached projection builds a new owned `Snapshot`. The first receiver profile requires a common inspector address, port, literal DNS role and server anchor across routes. Per-frontend-role client anchors remain bound to that role and the same verified chain. At most eight distinct configured client anchors are accepted, with exact coverage and no ambient roots.

The private constructor consumes its single process attempt before parsing. It copies all input bytes, owns the parsed key/certificate/configuration, requires explicit server and client trust anchors, TLS 1.3, HTTP/1.1, mutual certificate verification, intended role EKUs and exact literal DNS role names. PEM lexical validation refuses skipped junk, malformed preceding blocks, duplicate keys, unsupported types, headers and trailing material before standard cryptographic parsing. No test in this checkpoint parses a real credential.

Only the actual receiver-owned `tls.Conn` handshake and its actual verified chains can establish the internal frontend role. Caller-supplied certificate/state/Peer values cannot enter this path. Before the response commitment, the local server chain is reverified with owned explicit roots/intermediates at the current time; the same connection's selected client chain and role/anchor are rechecked. All chain validity windows are rechecked inside the short owner barrier; cryptographic work and I/O remain outside that mutex.

There are two immediate reservations before any future Accept. Copies alias their one bind attempt; a nil endpoint does not refund it. The private endpoint wraps every actual underlying call, including deadlines/addresses, and owns one shared Close attempt across TLS internals and outer cleanup. A nil Close receipt is insufficient while any actual call remains active. Error, panic or uncertain Close keeps the endpoint and reservation, retires admission and prohibits retries. A Serve panic poisons the owner before cleanup; it cannot become ordinary successful closure.

## Wire and time limits

The original total deadline is the earlier of the parent's deadline and reservation start plus two seconds. Handshake and read stages each use the earlier of that total and their stage start plus one second. Completion at deadline equality fails; post-I/O cancellation/deadline checks prevent late success. No fresh two-second stage or zero-deadline reset is allowed.

The same TLS connection supplies one preserved raw control header of at most 4096 bytes and one 104-byte AGCHECK body. Standard `textproto` parsing counts framing fields before standard `http.ReadRequest` can normalize them. The path is exactly `POST /_aegvium/m2-h1-1/pair`, HTTP/1.1, the configured inspector Host/port, one Content-Length 104 and Connection close. Transfer coding, content encoding, trailers, upgrades and duplicate framing fields refuse. This control parser makes no strict original-application raw-framing claim and does not process a second request.

AGCHECK104 is `AGCHECK1` (8 bytes), generation lowercase hex (32), complete AGPAIR SHA256 (32 raw bytes), then SHA256 of `M2-H1/1` (32 raw bytes). Invalid length, magic, generation grammar or fixed contract hash yields 400. A well-formed different generation or common digest yields 409. A matching tuple can return only the locally prepared 104 bytes with 200; this does not assert Ready, current ownership or permission to allow traffic. Cancellation, retirement and certificate validity are rechecked before beginning the response; already-started I/O can only report historical completion facts.

The retained independent 313-byte descriptor has SHA256 `5ec0935b94a4a4541abaa76768731aaccbc772a02e0dd926b36dde2660ef6e9d`. The contract hash is `1d987134086420d48b300a4cfda016ffc550a0bda6a6f20c58282db1b7d42dca`. `internal/requestctx/testdata/pair_prepared.json` preserves the independently frozen 104-byte expected literal rather than deriving the oracle from the implementation. Its anchor bytes are opaque synthetic configuration, not certificates.

## Source evidence and qualification limits

The pre-code packet is retained outside the repository as `aegvium-owned-pair-receiver-packet-20261022.md`, SHA256 `7db03872501f384c0670c84234c5f5cf29475e9d8387f6633a8097a8e0bb1d8c`. Independent review froze the tuple, malformed/stale cases, shared Close ownership and original deadline before implementation.

The interrupted source edit was confirmed not to have started after a CreateProcess transport failure. Reconnection was followed by actual HEAD/file inspection before the known-unexecuted edit resumed. A later ordinary fixture write stopped on a missing testdata directory after the strict PEM helper had been written; the directory and remaining fixtures were then created. Neither failure launched tests or children. Reconnection supplies no host-retirement or reboot evidence.

Direct cached-tool checks on 2026-10-22 passed: gofmt on the eight Go files; tagged `TestPairSource` tests with `GOMAXPROCS=2`, `-p=2`, `-count=1`, `-timeout=60s`; tagged vet of requestctx/pairmodel; default requestctx compile-only; and `make check lint secrets`. The first test build exposed a test import-name collision with the existing `hex` function; aliasing `encoding/hex` fixed it. The earlier content-check failure and source manifests remain retained outside the repository. Ordinary Go startup ran within routine engineering scope; the denied standalone read-only sysctl was not retried. Full verification, race, actual TLS and native qualification remain unrun.

The executed tests use the retained JSON fixture, standard PEM serialization of a public one-byte container, synthetic certificate time fields and memory-only fake endpoints. Their only test goroutine has unconditional release and explicit join cleanup. They do not call the receiver constructor, X509KeyPair, ParseCertificate, Verify, Handshake, listener/socket creation, native engine or operational process control. The default test binary was compiled and retained, not executed. Source test success does not establish authenticated pairing or current ownership.

## Remaining first-usable workflow gates

The constructor currently accepts operator descriptor/material bytes; it is not bound to the actual committed S generation intent or bootstrap/launch history. That real S-to-I binding remains unissued. Trusted initial-C commissioning/pin production, executable loader/library custody and the actual inspector startup/data-FD/TLS syscall closure remain separate missing production prerequisites. No arbitrary leaf promises, fresh-install inference from file absence, positive launch/history provider or cleanup issuer is introduced here.

Installed entrypoints remain closed. Real authenticated pairing, request inspection/block/forward integration, backend isolation, resource bounds, process/descriptor/no-export cleanup and the mandatory four-second shutdown still require their accepted evidence. Supervisor-loss recovery remains refused: neither parsed history, free flock, process absence, operator assertion nor reconnection establishes physical retirement. Draft126's full/native/engine/security validation pause is unchanged.

The earlier pathname-link checkpoint did not repair an absent guard: both link-count guards already existed; the prior slice added path-only regression coverage after the reviewer retracted the omission finding.
