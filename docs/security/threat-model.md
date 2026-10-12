# Threat model

Untrusted: HTTP clients, bodies/headers, forwarded identity, backend responses, rules updates, log input and optional reputation feeds. Protect TLS keys, credentials, routing integrity, engine availability and backend isolation.

Main risks: inspection bypass, parser disagreement/request smuggling, fail-open errors, unbounded buffering, secret logging, excessive privilege and compromised rules/dependencies. Controls must be verified natively: deny unknown routes, constrain backend reachability, strip spoofable identity headers, fail closed, set resource budgets, redact logs, validate update provenance and retain a known-good inspected configuration.

A WAF cannot repair authorization or business-logic flaws generally. CrowdSec detection requires a reviewed enforcement component; it is not an automatic virtual-patching guarantee.
