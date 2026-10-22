# Product requirements

Status: proposed technical scope; foundation authorized 2026-10-11.

- WAF-01: separate OpenBSD VM behind an operator-controlled perimeter; reverse proxy for explicitly configured HTTP/HTTPS applications. EdgeWall is an optional suite integration, not a runtime prerequisite.
- WAF-02: inline request inspection using a qualified open-source engine and pinned OWASP CRS; blocked requests never reach the backend.
- WAF-03: no direct backend bypass; unknown hosts/routes denied, inspection failure cannot silently forward uninspected traffic.
- WAF-04: bounded bodies, headers, connections, timeouts and audit storage; document unsupported streaming/protocol behavior.
- WAF-05: trusted client identity from a defined ingress boundary; remove untrusted forwarding headers. Audit logs redact secrets and distinguish detection from enforcement.
- WAF-06: least privilege, validated configuration, reproducible pinned artifacts, controlled rules updates and recovery to a known-good inspected configuration.
- WAF-07: BootWeave installation integration after its contract is available; product policy remains here.
- WAF-08: optional CrowdSec only after package, parser, enforcement, privacy and outage behavior review.
- WAF-09: independently installable and operable without other suite products. Publish minimal explicit frontend/backend interfaces and conformance inputs so a qualifying third-party stack can integrate. Vectivium, EdgeWall and BootWeave integrations are optional; an explicitly requested security integration must refuse on failure, never silently bypass inspection. Standalone and interoperability acceptance are required product gates.

Non-goals: replacing EdgeWall, containers, Linux appliance infrastructure, universal OWASP Top 10 prevention, automatic community-feed trust, production cutover during research.

Success requires native evidence for benign traffic, attack blocking, bypass resistance, failures and resource limits; performance budgets and supported application/protocol profiles remain to be selected in M1.

The M2 inspector protocol accepts configured authenticated frontend roles without
a Vectivium binary or suite control plane. The selected suite adapter is one
implementation of that boundary. A turnkey standalone installation and a
qualified third-party adapter are not delivered yet; WAF-09 remains open. This
requirement does not waive key custody, isolation or any runtime qualification.
