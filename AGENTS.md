# Agent instructions

1. Read README, CONTRIBUTING and the active PRD/EDD/Test Design before editing.
2. OpenBSD is the runtime target. Host checks and cross-builds are tooling evidence only.
3. Foundation setup is authorized by the 2026-10-11 user request. Architecture is proposed; nontrivial runtime implementation follows scoped reviewed design or explicitly authorized bounded research.
4. Prefer base tools and Go standard library; new dependencies require license/provenance review and an ADR.
5. Keep the WAF on a separate VM behind EdgeWall. Never test against live gateway, storage or applications.
6. Require signed Conventional Commits, author DCO sign-offs and codex/ topic branches. Never disable signing silently. Post-bootstrap changes use PRs; leave them open.
7. Run make verify locally. GitHub Actions, runners and hosted success publishers are prohibited.
8. Keep credentials, TLS private keys, production traffic and private inventories out of Git and evidence.
9. BootWeave owns the generic installer. WAF owns its payload and runtime policy. Do not invent its extension schema.
10. Track requirements, tests, native evidence, compatibility and rollback separately. Do not claim OWASP Top 10 coverage from a build or attack string demo.
11. Do not deploy, enable services, merge, release or modify live networks without authorization.
12. Do not spawn agents unless the user explicitly requests parallel agent work.
