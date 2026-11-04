# Independent literal vectors

`independent.json` was produced by an independent design reviewer on 2026-10-20
using the retained BSD-licensed `oracle.py` and Python standard library. Product
tests read its literal expected bytes, digests and decisions; they never invoke
the oracle or derive expected values through the Go implementation. The retained
oracle covers three independently scoped suite models and regenerates JSON in
its own directory only if explicitly run; it is not part of runtime or tests.

All values are synthetic unbound intent. Matching bytes grant no native, caller,
namespace, peer, freshness, permission or readiness authority.
