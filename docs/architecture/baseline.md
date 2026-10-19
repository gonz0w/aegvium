# Candidate architecture

Status: M2 boundary selected by [ADR 0010](adr-0010-frontend-key-mandatory-inspector.md);
runtime integration unimplemented/unqualified. The current selected source design
is EdgeWall → Vectivium frontend/public TLS owner → separate authenticated Aegvium
inspector → allowlisted authenticated application. [M2-H1/1](../milestones/M2/FRONTEND-INSPECTOR-CONTRACT.md)
scopes the next pure source component; no live topology or feature is enabled.
The [M1 connector ADR](adr-0001-ingress-inspection.md) and the following historical
comparison retain their narrower evidence, not a current M2 default.

EdgeWall → WAF VM relayd TLS listener → loopback inspection proxy embedding Coraza + CRS → allowlisted application backend.

relayd is a base-system proxy and TLS front end. Coraza is a library requiring an integration; relayd has no documented built-in SecLang/Coraza connector. A small Go HTTP reverse proxy is a candidate, not an adopted custom runtime. Compare it with a supported packaged connector before choosing. Evaluate TLS in a single inspection service if relayd introduces parser disagreement or identity ambiguity.

No path may bypass inspection. Only the ingress component can reach the local inspection listener; backend access is constrained by routes and network policy. EdgeWall remains perimeter authority; appliance-local PF may contain services without replacing it.

Review client identity, forwarding headers, TLS trust, SNI/Host routing, request smuggling across parsers, request/response bodies, websocket/streaming policy, timeouts and engine-error behavior. Never equate CRS loading with full functional coverage.

Use base rc.d, syslog/newsyslog and acme-client where suitable after design. Management is a separate least-privilege boundary; no web console is selected. BootWeave builds media later from verified WAF artifacts.

## Management UI baseline

The maintainer specified OpenBSD relayd/httpd for Nomvium and Arxwall management web serving. This is an intended sibling-project baseline, not evidence that their current implementations already use it. relayd can own TLS and ingress policy; httpd can serve static assets and FastCGI. The dynamic UI contract and privilege boundary still need project-specific design. This management path is separate from Aegvium application inspection and does not establish a relayd–Coraza connector.

The [isolated existing-connector API study](../../research/connector/README.md) now has bounded OpenBSD request/error/response and rule-pool observations. It keeps Caddy dependencies out of the companion module and retains reachable advisory findings as adoption blockers. Full configured-server/relayd TLS/trust/resource parity remains separate from this standard-library harness.
