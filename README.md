# Aegvium

Lean, auditable HTTP/HTTPS inspection appliance for a separate homelab VM behind EdgeWall. BSD-3-Clause; independent of the OpenBSD project.

Private repository: [gonz0w/aegvium](https://github.com/gonz0w/aegvium).

Status: repository foundation, proposed architecture and an authorized research-only engine spike. No WAF binary, supported appliance, native qualification or installer exists yet.

Candidate flow: client → EdgeWall → relayd (TLS) → local Coraza inspection proxy with OWASP CRS → explicitly configured backend. The connector and body handling require native evidence before adoption. CrowdSec is an optional later behavioral layer, not the inline WAF engine.

BootWeave will build installation media when its generic extension contract is ready. This repository owns WAF payloads and runtime policy; no speculative installer schema is defined.

Start with [requirements](docs/product/PRD.md), [architecture](docs/architecture/baseline.md), [M1 design](docs/milestones/M1/EDD.md), [test design](docs/milestones/M1/TDD.md), [research](docs/research/stack.md), and [contributing](CONTRIBUTING.md).

Run `make tools hooks` then `make verify`. Checks run locally, with no GitHub Actions or runners. Host checks do not establish OpenBSD support.

Track work in the [private Project](https://github.com/users/gonz0w/projects/5), [roadmap index](docs/milestones/github-roadmap-index.md), and [GitHub workflow](docs/engineering/github-workflow.md). The [Coraza spike](research/coraza/README.md) exercises synthetic request semantics; `make research-test` and `make research-cross` are separate research gates.

The next slice adds pinned CRS smoke tests and [dependency/advisory review](docs/research/dependency-review.md). Run `make research-tools` before research commands; `make research-audit` queries the Go advisory database. [Native engine preparation](docs/milestones/M1/NATIVE-ENGINE.md) remains distinct from native execution.
