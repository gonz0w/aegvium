# Stock relayd syntax fixture

Research only. [Scoped PRD/EDD/Test Design](../../docs/milestones/M1/RELAYD-CONFIG.md) defines the boundaries. `ingress.conf` names only a loopback inspection target and HTTP readiness check. Do not install it as an appliance configuration.

`make research-relayd-config` uses the owned native controller after a clean signed commit and `make verify`. It authenticates/patches/reboots the independently admitted guest, invokes installed `/usr/sbin/relayd -n -f` on the fixture and two invalid variants, verifies process/listener/control-socket absence, then runs the 20-case engine fixture as nonroot. It does not start relayd or send traffic through it. Guest egress stays restricted; original image source lineage remains unresolved.

A future readiness endpoint must answer relayd's HEAD check and reflect inspection configuration readiness. This fixture does not implement that endpoint or establish health behavior. Syntax acceptance does not prove no-bypass enforcement, trust/header/parser semantics, TLS or a working Coraza connector.

## Observed result

Candidate `62a0f7e3be7bb191fd56b1c7e172c16659d6c439` passed all three expectations in the owned patched OpenBSD 7.9 amd64 guest: valid fixture accepted, missing protocol and bad syntax rejected with exit 1. Before/after checks verified no relayd process, fixture-port IPv4 listener or control socket. Installed relayd SHA-256 is `18f66755fcd95225005da2784e8071a2e97eaf749c0c32a53b721c2151d0f010`. All 20 engine cases also passed as UID 32767 using the separate host cross-build.

[Receipts](config-observations.json) bind source/tree, configuration/variant/binary hashes, native logs, patched/rebooted baseline and verified teardown/source/base invariance. Subsequent documentation/evidence changes do not claim a new native run; runtime hashes must match. Exact relayd source/build lineage, a running health check and connected ingress/inspection/application traffic remain unobserved.
