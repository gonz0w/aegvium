# Isolated existing-connector comparison

Private bounded research. Read [CE-01–04](../../docs/milestones/M1/CONNECTOR-EXECUTION.md), [ADR-0002](../../docs/architecture/adr-0002-isolated-connector-comparison.md) and the [reviewed dependency graph](../coraza/connector-dependencies.json) before changing pins. The companion module is separate and unchanged.

```
make research-connector-test
make research-connector-cross
make research-native-connector
```

Prepare the pinned tools and disposable native image as described in [native preparation](../../docs/milestones/M1/NATIVE-ENGINE.md). The optional controller first verifies the target's loaded module versions/checksums/legal files against the reviewed manifest. It cross-builds the comparison fixture on the host, runs the unchanged 163 ordinary engine cases, then executes the comparison as nobody in a patched/rebooted owned OpenBSD guest. This command does not compile Caddy natively; native source compilation remains a separate gate. No Caddy service/admin API/certificate automation or external backend starts.

The fixture loads the actual `http.handlers.waf` connector through Caddy's context, calls its request preparation API, and maps returned HandlerError statuses in a standard-library HTTP adapter. It compares twenty identical close-only wire requests per arm against an owned HTTP backend using Coraza v3.8.1/CRS v4.25.0, explicit 128-byte request/memory limits and two synthetic response rules. The synthetic response tests do not qualify the upstream response corpus. Request hashes and backend body/authority/effect counts are independent of client response outcomes. Source Close counts describe these concrete wrappers: Caddy's admitted POST replay reaches three original Close calls, versus one in the middleware arm; general reader idempotence is unqualified.

Twenty-two rule reload observations characterize fresh middleware construction versus overlapping connector pool generations. The same configuration string can reuse the old WAF even after an included file changes. Altering the directive string explicitly builds a new generation; rejected rules preserve the earlier instance, and an explicit configuration rollback reloads old rule bytes. This is a diagnostic, not a supported rules distribution or invalidation scheme. The companion currently reloads routes, not external rules.

[Wire expectations](wire-expectations.json) retain the reviewed host matrix, including implicit-200/no-backend malformed-reader middleware outcomes and the connector adapter's explicit 500. Native admission must match every field; it cannot turn these characterizations into safety claims. Both arms accept Go-normalized CL+TE and preserve the spoofed header deliberately carried by the test proxy; neither behavior establishes sender authentication or safe request smuggling policy. Response denials each follow one inspected backend effect and do not undo application work.

[Advisory review](advisory-review.json) retains the inadequate initial test-only scan and corrected loaded host/target scans: nine IDs, eight imported-package IDs and seven symbol-level IDs. Pins are fixed for comparison; remediation and fresh qualification block adoption. No benchmark, binary-footprint superiority or production security recommendation follows. Raw module source/binaries/logs stay ignored. No dependency binary/source distribution is approved; preserve applicable MPL/license/NOTICE obligations before any future publication.

Native execution results will be linked after controller admission. Full Caddy server/relayd topology, TLS authority/sender containment, native connector compilation, full CRS/false positives, resource/soak budgets and original installed lineage remain open under existing parent issues.
