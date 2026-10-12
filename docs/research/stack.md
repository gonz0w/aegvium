# Stack feasibility research

Reviewed 2026-10-11; upstream documentation is evidence of intent, not native qualification.

- [relayd manual](https://man.openbsd.org/relayd.conf.5): base HTTP/TLS proxy and protocol policy. No documented native Coraza connector was found.
- [Coraza quick start](https://www.coraza.io/docs/tutorials/quick-start/) and [connectors](https://www.coraza.io/connectors/): library needs integration. No relayd connector is listed. OpenBSD build, regex/CRS compatibility, body phases and resource behavior remain unverified.
- [OWASP CRS](https://coreruleset.org/): candidate rule set. Pin a tested release and preserve its license/notices; tune exclusions against benign applications and prove enforcement.
- [CrowdSec introduction](https://docs.crowdsec.net/u/getting_started/intro/): separate detection and remediation. The [OpenBSD ports Makefile](https://github.com/openbsd/ports/blob/276673bd42807eb155701e99fc3595fea9553661/security/crowdsec/Makefile) records v1.8.1 and MIT licensing. Current ports source is not proof of package availability in a selected stable release; architecture, parser and remediation support remain native gates. Optional after inline inspection works.

Do not claim complete OWASP Top 10 protection or stable OpenBSD support from upstream feature lists. M1 selects the connector and records exact versions and licenses through an ADR.

Research pins observed 2026-10-11: [Coraza v3.8.1](https://github.com/corazawaf/coraza/releases/tag/v3.8.1) and [coraza-caddy v2.6.2](https://github.com/corazawaf/coraza-caddy/releases/tag/v2.6.2). The isolated engine spike uses v3.8.1; no Caddy dependency is adopted. [CRS engine notes](https://coreruleset.org/20260511/migrating-crs-3-to-4-part-7-engines/) describe Coraza compatibility, but Aegvium has not run a pinned CRS corpus.
