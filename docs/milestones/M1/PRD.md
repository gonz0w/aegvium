# M1 native stack qualification PRD

Status: Researching. The maintainer request of 2026-10-11 authorizes bounded research, not product adoption.

M1-01: establish exact reproducible Coraza/rules/connector lineage and dependency review.
M1-02: prove admitted request/body phases and denial semantics using synthetic engine tests; separate host from native evidence.
M1-03: compare candidate ingress/inspection integration on disposable OpenBSD with backend receipt assertions, trusted identity and parser disagreement tests.
M1-04: qualify pinned CRS against benign and attack cases; preserve failures/skips and supported-protocol limits.
M1-05: review connector/privilege ADR and scoped M2 packet before product implementation.

No real applications, public listener, production configs or live firewall changes. Initial engine spike uses synthetic rules only; it does not qualify CRS, relayd or appliance routing.
