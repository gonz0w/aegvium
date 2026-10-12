# Capability roadmap

No delivery dates. Later phases are planning outcomes until scoped reviewed PRD/EDD/Test Design admits implementation. Component completion never accepts its phase.

## M0 — Repository and research foundation

- Rename and reconcile the Nomvium development foundation
- Establish the private issue and acceptance roadmap
- Review the product and native research baseline

## M1 — Native stack and connector qualification

- Characterize pinned Coraza request/body interruption semantics
- Define and provision a disposable native OpenBSD research profile
- Review engine rules and connector dependency provenance
- Reproduce the engine and candidate connector builds on OpenBSD
- Compare relayd plus Go integration with an existing Coraza connector
- Characterize HTTP parser disagreement and bypass risks
- Qualify a pinned CRS release against the selected native candidate
- Review connector and privilege-boundary adoption ADR

## M2 — Inline enforcement and backend isolation

- Review the bounded enforcement implementation packet
- Implement allowlisted routing and deny unknown hosts
- Qualify ingress TLS and trusted client identity
- Implement complete admitted request inspection and bounded bodies
- Qualify startup reload crash and management-absent enforcement
- Complete independent native enforcement and bypass acceptance

## M3 — Policy operations and recovery

- Review policy update and operational recovery design
- Qualify pinned rules updates rejection and known-good recovery
- Provide bounded explainable application exclusions
- Qualify redacted bounded audit and health evidence
- Review authenticated CLI and optional BSD Classic console scope
- Complete native rule-operation drift and recovery acceptance

## M4 — Appliance packaging and BootWeave integration

- Review packaging and generic installer boundary
- Build reproducible verified OpenBSD appliance payloads
- Integrate through the accepted BootWeave extension contract
- Qualify appliance upgrade export restore and rollback limits
- Complete disposable media install reboot and uninstall acceptance

## M5 — Stability and personal-use candidate

- Freeze the complete private qualification candidate
- Qualify combined abuse load and failure isolation
- Complete a combined seven-day native stability soak
- Review usability and explicit private candidate acceptance

## Later — Optional behavioral protection and additional protocols

- Review CrowdSec native package parser remediation and privacy fit
- Research response inspection streaming upgrades and HTTP versions
