# Agent instructions

1. Read README, CONTRIBUTING and the active PRD/EDD/Test Design before editing.
2. OpenBSD is the runtime target. Host checks and cross-builds are tooling evidence only.
3. Foundation setup is authorized by the 2026-10-11 user request. Architecture is proposed; nontrivial runtime implementation follows scoped reviewed design or explicitly authorized bounded research.
4. Prefer base tools and Go standard library; new dependencies require license/provenance review and an ADR.
5. Aegvium runs independently; an EdgeWall integration is optional. Use disposable isolated systems for native tests. Never test against live gateway, storage or applications.
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

## Backlog delivery

Follow the authoritative [central delivery contract](https://github.com/gonz0w/suite-standards/blob/5b5a36ea63989357c62eba132bec6f59c9e4f1e3/docs/backlog-delivery.md)
and [rollout](https://github.com/gonz0w/suite-standards/blob/5b5a36ea63989357c62eba132bec6f59c9e4f1e3/docs/backlog-delivery-rollout.md)
at Suite-Standards `5b5a36ea63989357c62eba132bec6f59c9e4f1e3`.
Product independence and installer ownership follow the [central boundary](https://github.com/gonz0w/suite-standards/blob/5b5a36ea63989357c62eba132bec6f59c9e4f1e3/docs/standards.md#product-independence-and-bootweave-boundary). Product profiles, setup/commissioning code and Bootweave usage instructions stay in this repository; Bootweave is an external generic installer with no product dispatch or runtime dependency. Existing execution/authority and qualification holds remain.

Adoption owner: delegated LAB product lane; [issue #128](https://github.com/gonz0w/aegvium/issues/128).

Next outcome/queue: Standalone install/start/inspect/backend/restart: #22/#23/#28/#31; existing Draft126.
WIP:2 active batches per repo,1 per implementer; Blocked/Review count.
Draft125/126 remain visible held/review work, not accepted WAF appliances. Bundled standalone frontend and bounded durable security-record source directions were adopted2026-10-23; actual TLS/credentials/native launch, four-second qualification and activation remain held.
Checks/holds: make check lint secrets; targeted pure/intercepted tests, scoped vet and cross-builds. Full/native/engine campaigns and activation remain held; Actions/runners stay prohibited.

Local mapping: legacy Validation means source awaiting acceptance; issue text names
Blocked reasons and it still counts as WIP. Inherited-WIP exception permits only
this instruction/backlog maintenance within existing batches; no new custom
architecture batch. Owner: delegated LAB lane; review at2026-10-24 handoff.
Existing safety, independent review, signatures, evidence and acceptance rules
remain; this pointer does not enforce unrelated advisory profiles or grant effects.
