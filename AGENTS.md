# Agent instructions

1. Read README, CONTRIBUTING and the active PRD/EDD/Test Design before editing.
2. OpenBSD is the runtime target. Host checks and cross-builds are tooling evidence only.
3. Foundation setup is authorized by the 2026-10-11 user request. Architecture is proposed; nontrivial runtime implementation follows scoped reviewed design or explicitly authorized bounded research.
4. Prefer base tools and Go standard library; new dependencies require license/provenance review and an ADR.
5. Keep the WAF on a separate VM behind EdgeWall. Never test against live gateway, storage or applications.
6. Require signed Conventional Commits, author DCO sign-offs and codex/ topic branches. Never disable signing silently. Post-bootstrap changes use PRs; leave them open.
7. Run make verify locally. GitHub Actions, runners and hosted success publishers are prohibited.
8. Keep credentials, TLS private keys, production traffic and private inventories out of Git and evidence.
9. BootWeave owns the generic installer. Aegvium owns its payload and runtime policy. Do not invent its extension schema.
10. Track requirements, tests, native evidence, compatibility and rollback separately. Do not claim OWASP Top 10 coverage from a build or attack string demo.
11. Do not deploy, enable services, merge, release or modify live networks without authorization.
12. Do not spawn agents unless the user explicitly requests parallel agent work.

13. The 2026-10-11 user request authorizes the Aegvium rename, tracking setup and bounded research. Keep results separate from runtime adoption.
14. Inspect open PRs and unblocked Ready issues on continue; keep issue state, native blockers and Project fields consistent.

15. Present security validation as concise statuses, counts and hashes instead of raw request fixtures or verbose findings. Respect security access notices; never request broader cyber access or hide/repackage restricted content to bypass a safeguard. Stop affected validation and record it as blocked while continuing ordinary engineering.

## Task context

Use the [local task context](docs/engineering/agent-tasks.md) for the compact shared
packet and repository command/path index. Existing instructions, required reviews
and source/native execution and acceptance gates remain authoritative.

## Storage prevention

Follow [local storage gates and retention](docs/engineering/storage.md) before
substantial output. Include external run roots and concurrent demand. Preserve
source, current work, canonical inputs and backing chains; no broad purge.
