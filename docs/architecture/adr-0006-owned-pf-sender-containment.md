# ADR 0006: Research local PROXY sender containment with PF

Status: bounded research decision; product adoption pending.

The TLS passthrough fixture binds SNI/Host but still accepts a direct local sender's forged PROXY prefix. Stock address assertions and loopback do not authenticate that sender. Keep the finding and test a separate kernel-enforced local boundary.

Use stock PF outgoing socket UID matching on the owned VM's loopback data port. Allow only `_relayd` and reject all other fresh connections. Compare open/protected/rollback/protected-again controls with exact TLS/HTTP/backend effects and PF counters; validate temporary PF changes and complete restoration. All other isolated guest traffic is passed only to keep the experiment's harness functional; this is not an appliance PF policy.

UID matching depends on socket-creation credentials and active loopback filtering. Root/PF administrators and an allowed-UID compromise are outside this boundary. A dedicated production companion identity, startup ordering and privileged policy ownership still need review. TLS terminates in the companion; PROXY remains a trusted-process assertion only if the sender boundary is actually enforced.

Alternatives remain an authenticated local channel, source changes to relayd, or a single-process connector. No source patch, third-party dependency, generic privilege helper, unprivileged PF-control channel or separate connector repository is introduced. See the [scoped PRD/EDD/test design](../milestones/M1/SENDER-CONTAINMENT.md). No live network or persistent service change is authorized by this experiment.
