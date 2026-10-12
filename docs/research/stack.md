# Stack feasibility research

Reviewed 2026-10-11; upstream documentation is evidence of intent, not native qualification.

- [relayd manual](https://man.openbsd.org/relayd.conf.5): base HTTP/TLS proxy and protocol policy. No documented native Coraza connector was found.
- [Coraza quick start](https://www.coraza.io/docs/tutorials/quick-start/) and [connectors](https://www.coraza.io/connectors/): library needs integration. No relayd connector is listed. OpenBSD build, regex/CRS compatibility, body phases and resource behavior remain unverified.
- [OWASP CRS](https://coreruleset.org/): candidate rule set. Pin a tested release and preserve its license/notices; tune exclusions against benign applications and prove enforcement.
- [CrowdSec introduction](https://docs.crowdsec.net/u/getting_started/intro/): separate detection and remediation. Prior prompt claims an OpenBSD port; current release availability, architecture, parser and bouncer support still need direct ports/package and native verification. Optional after inline inspection works.

Do not claim complete OWASP Top 10 protection or stable OpenBSD support from upstream feature lists. M1 selects the connector and records exact versions and licenses through an ADR.
