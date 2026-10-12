# Stock relayd syntax fixture

Research only. [Scoped PRD/EDD/Test Design](../../docs/milestones/M1/RELAYD-CONFIG.md) defines the boundaries. `ingress.conf` names only a loopback inspection target and HTTP readiness check. Do not install it as an appliance configuration.

`make research-relayd-config` uses the owned native controller after a clean signed commit and `make verify`. It authenticates/patches/reboots the independently admitted guest, invokes installed `/usr/sbin/relayd -n -f` on the fixture and two invalid variants, verifies process/listener/control-socket absence, then runs the 20-case engine fixture as nonroot. It does not start relayd or send traffic through it. Guest egress stays restricted; original image source lineage remains unresolved.

A future readiness endpoint must answer relayd's HEAD check and reflect inspection configuration readiness. This fixture does not implement that endpoint or establish health behavior. Syntax acceptance does not prove no-bypass enforcement, trust/header/parser semantics, TLS or a working Coraza connector.
