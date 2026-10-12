# Product requirements

Status: proposed technical scope; foundation authorized 2026-10-11.

- WAF-01: separate OpenBSD VM behind EdgeWall; reverse proxy for explicitly configured HTTP/HTTPS applications.
- WAF-02: inline request inspection using a qualified open-source engine and pinned OWASP CRS; blocked requests never reach the backend.
- WAF-03: no direct backend bypass; unknown hosts/routes denied, inspection failure cannot silently forward uninspected traffic.
- WAF-04: bounded bodies, headers, connections, timeouts and audit storage; document unsupported streaming/protocol behavior.
- WAF-05: trusted client identity from a defined ingress boundary; remove untrusted forwarding headers. Audit logs redact secrets and distinguish detection from enforcement.
- WAF-06: least privilege, validated configuration, reproducible pinned artifacts, controlled rules updates and recovery to a known-good inspected configuration.
- WAF-07: BootWeave installation integration after its contract is available; product policy remains here.
- WAF-08: optional CrowdSec only after package, parser, enforcement, privacy and outage behavior review.

Non-goals: replacing EdgeWall, containers, Linux appliance infrastructure, universal OWASP Top 10 prevention, automatic community-feed trust, production cutover during research.

Success requires native evidence for benign traffic, attack blocking, bypass resistance, failures and resource limits; performance budgets and supported application/protocol profiles remain to be selected in M1.
