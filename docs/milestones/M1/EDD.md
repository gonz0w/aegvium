# M1 engineering design

Status: proposed bounded feasibility work.

Build a disposable OpenBSD amd64 laboratory and record exact OS/package/Go/Coraza/CRS revisions, hashes, dependency licenses and build commands. Compare relayd plus a minimal Coraza HTTP integration against an existing connector; record maintenance burden, parser semantics, privileges and resource use. No live network changes.

Define inspection phases and interruption/error handling before writing the proxy. Verify body buffering, temporary-file permissions, transaction cleanup, backend TLS validation and concurrency. Bound unsupported upgrades/streaming explicitly. Document logs with synthetic data only.

Deliverables: reproducible native build, dependency ADR, packet-flow/trust design, test results and a recommendation. Adoption and product implementation are separate review gates. No runtime configuration syntax is selected here.

## Authorized first slice

The 2026-10-11 request to begin research authorizes the isolated research/coraza module, pinned v3.8.1 upstream HTTP middleware and synthetic in-memory backend. It opens no listener and installs no service. Test URI/body interruption, body preservation/limit, DetectionOnly, invalid rules and reader-error behavior. Runtime selection remains pending native comparison.
