# Stock relayd syntax fixture

Research only. [Scoped PRD/EDD/Test Design](../../docs/milestones/M1/RELAYD-CONFIG.md) defines the boundaries. `ingress.conf` names only a loopback inspection target and HTTP readiness check. Do not install it as an appliance configuration.

`make research-relayd-config` uses the owned native controller after a clean signed commit and `make verify`. It authenticates/patches/reboots the independently admitted guest, invokes installed `/usr/sbin/relayd -n -f` on the fixture and two invalid variants, verifies process/listener/control-socket absence, then runs the 20-case engine fixture as nonroot. It does not start relayd or send traffic through it. Guest egress stays restricted; original image source lineage remains unresolved.

A future readiness endpoint must answer relayd's HEAD check and reflect inspection configuration readiness. This fixture does not implement that endpoint or establish health behavior. Syntax acceptance does not prove no-bypass enforcement, trust/header/parser semantics, TLS or a working Coraza connector.

## Observed result

Candidate `62a0f7e3be7bb191fd56b1c7e172c16659d6c439` passed all three expectations in the owned patched OpenBSD 7.9 amd64 guest: valid fixture accepted, missing protocol and bad syntax rejected with exit 1. Before/after checks verified no relayd process, fixture-port IPv4 listener or control socket. Installed relayd SHA-256 is `18f66755fcd95225005da2784e8071a2e97eaf749c0c32a53b721c2151d0f010`. All 20 engine cases also passed as UID 32767 using the separate host cross-build.

[Receipts](config-observations.json) bind source/tree, configuration/variant/binary hashes, native logs, patched/rebooted baseline and verified teardown/source/base invariance. Subsequent documentation/evidence changes do not claim a new native run; runtime hashes must match. Exact relayd source/build lineage, a running health check and connected ingress/inspection/application traffic remain unobserved.

## First connected traffic result

[Traffic packet](../../docs/milestones/M1/RELAYD-TRAFFIC.md) and [observations](traffic-observations.json) record candidate `343fcc6ad8a57de2a347ce67341f375d3592ca01` passing ten connected cases inside the owned guest. Stock foreground relayd forwarded plain HTTP to the nonroot Coraza/Go reverse-proxy fixture and synthetic backend. Both direct control and relayd arms passed benign GET/POST byte assertions and URI/body denial with zero backend receipts.

With the backend still alive, closing inspection produced observed 500/502/502 responses and zero backend forwards. Daemon health logs showed inspection down/up transitions; restored inspection then admitted exactly one expected POST receipt. Readiness HEAD probes never reached the backend. Existing 20 engine cases and configtests also passed. The foreground daemon stopped, ingress/inspection IPv4 listeners disappeared, the control socket was removed and owned VM teardown/source/base invariance passed.

Run `make research-relayd-traffic` only after the scoped packet, a clean signed candidate and `make verify`. No rc.d service or live PF/network change is made. The host Go test explicitly skips this connected test; native execution uses the separate admitted set. Binary/config/log/source hashes distinguish this cross-build execution from historical native source-build evidence. Later docs/receipts do not claim another native run; runtime inputs must match.

This establishes a small stock-relayd companion path and demonstrates useful health-checked dispatch in this fixture. It does not select a reusable API, publish a connector, establish exact relayd source/build provenance or qualify trusted client identity, direct-access prevention, TLS, malformed framing, response phases, CRS corpus, persistent connection behavior, performance or comprehensive failures. Those remain separate research/adoption gates.
