# Agent task context for aegvium

Use the [shared compact task packet](https://github.com/gonz0w/suite-standards/blob/e9653b677a3b295d5a7c2d507f86cdc3805bd94e/docs/task-packets.md)
from immutable Suite-Standards revision `e9653b677a3b295d5a7c2d507f86cdc3805bd94e`.
This advisory pointer leaves existing standards manifests/pins and stronger local
instructions, reviews and acceptance gates unchanged.

## Local path and command index

- Scope the packet to `internal/`, `research/`, `tools/tests/`, `docs/milestones/`. Read the applicable
  instructions and relevant design sections; do not load all sibling documentation.
- Run commands from this repository root using the pinned development tools.
  The authoritative foundation command is `make verify`; see `Makefile`,
  `README.md` and `CONTRIBUTING.md` for setup and required final checks.
- `make test` includes `contract-check`; select additional reviewed source checks from the active M2 contract.
- OpenBSD WAF/relayd/TLS/PF/lifecycle campaigns require their exact authority; source corpus checks do not qualify WAF coverage or release.

Naming a command does not authorize native effects, downloads, credentials or
retries. Record exact commands actually run, tested base/head/tree, outcomes and
remaining blocked/not-run gates. Keep dirty work, active owners and failed evidence
intact; a focused source check does not replace a required final gate.
