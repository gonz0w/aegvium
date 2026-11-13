# Project policy

This is a compact selection and index of settled policy, not a replacement for
[AGENTS](AGENTS.md), [CONTRIBUTING](CONTRIBUTING.md), the linked contracts or their
stronger constraints. Apply them together; stop affected work and resolve a real
conflict with the authorized owner rather than choosing the easier rule.

## Adoption and transition

Adopt the pinned [Agent Temper method](.agent-temper/METHOD.md) and **only** the
[Codex routing profile](.agent-temper/profiles/codex.md), from reviewed revision
`1c9e9fb7e5e1152691dbc669d5f7222a7c0c377d`; [source and integrity](.agent-temper/SOURCE.md)
identify the exact bundle. The bundled GitHub and strict-test-first profiles are
inactive. No external extension is selected; the local choices below belong to
the consumer revision containing this file.

The owner authorized this bounded directions/routing adoption in
[gonz0w/aegvium#129](https://github.com/gonz0w/aegvium/issues/129).
It becomes project policy when merged, with no retroactive product acceptance.
Existing contracts and tracker authority are retained, with only the scoped
publication-timing exception below. The issue holds live adoption progress and
runtime evidence; do not add a repository progress log.
Policy/model/profile changes require an explicit authorized decision recorded
through the existing reviewed, signed contribution process. Cam (@gonz0w)
retains owner/maintainer authority under [governance](GOVERNANCE.md).

## Existing policy index

| Decision | Authoritative selection and limits |
| --- | --- |
| Purpose and boundaries | Lean OpenBSD WAF research for a dedicated VM behind EdgeWall; research and component evidence do not make an installable or accepted WAF. |
| Product, architecture and design admission | [product requirements](docs/product/PRD.md), [architecture](docs/architecture/baseline.md), [selected M2 boundary](docs/architecture/adr-0010-frontend-key-mandatory-inspector.md), [milestone index](docs/milestones/github-roadmap-index.md) and [document lifecycle](docs/process/document-lifecycle.md). Nontrivial runtime work still requires scoped reviewed design or explicit bounded research authorization. Runtime adoption, CRS coverage, recovery, resource/soak qualification, installation and personal-use acceptance remain separate gates. |
| Technology and dependencies | Prefer OpenBSD base tools and Go standard library; new dependencies retain license/provenance review and ADR requirements. BootWeave owns the generic installer; Aegvium owns payload/runtime policy. Existing source/tool pins remain unchanged. |
| Supported platforms | OpenBSD is the product runtime target. macOS/Linux host fixtures and cross-builds supply limited tooling evidence only; they do not establish native support or WAF coverage. |
| Live work and durable contracts | [GitHub workflow](docs/engineering/github-workflow.md), [private Project](https://github.com/users/gonz0w/projects/5) and [stable issue index](docs/milestones/github-roadmap-index.md): GitHub owns live status, priority and native dependencies; Git owns designs and source-bound evidence. |
| Verification and completion | `make verify` remains required locally; setup and focused commands are indexed in [README](README.md), [CONTRIBUTING](CONTRIBUTING.md) and [task context](docs/engineering/agent-tasks.md). Meaningful runtime changes retain abuse/failure/recovery tests and disposable OpenBSD evidence. Keep passed, failed, skipped, unavailable and not-applicable results distinct; acceptance requires the actual scoped evidence and existing review/integration gates. |
| Native authority and resources | [Native gate](docs/testing/native-gate.md), [native engine](docs/milestones/M1/NATIVE-ENGINE.md) and the active scoped Test Design retain exclusive ownership, containment, reserved build/verification budgets, teardown and evidence limits. Never use live gateways, storage or applications. Security access/output restrictions in [AGENTS](AGENTS.md) and [review policy](docs/engineering/review.md) remain binding. |
| Documentation and evidence | Keep existing Markdown design/ADR/Test Design and evidence locations, stable identifiers, failed/skipped receipts and source bindings. Update affected contracts with behavior; use the existing document lifecycle. Research is evidence until admitted/adopted. |
| Contribution, license and review | [Local review](docs/engineering/review.md) and [governance](GOVERNANCE.md) retain signed Conventional Commits, author DCO, required checks, source-bound evidence, protections and maintainer review/merge. GitHub Actions, runners and hosted success publishers remain prohibited. [BSD-3-Clause](LICENSE) remains the project license; retain imported notices. |
| Security and operations | [Security](SECURITY.md), [AGENTS](AGENTS.md) and existing design contracts remain binding. No new secret access, external communication, spending, deployment, service enablement, destructive action or release authority. |

## Codex routing

Use the exact local templates from the pin under `.codex/agents/`:

| Role/configuration | Model | Effort | Bounded work |
| --- | --- | --- | --- |
| [temper_workflow](.codex/agents/temper_workflow.toml) | `gpt-6-luna` | `medium` | Routine read-only inspection, inventories and summaries. |
| [temper_product](.codex/agents/temper_product.toml) | `gpt-6.1-terra` | `medium` | Accepted documentation, visual/browser tasks and small specified UI fixes. |
| [temper_implementer](.codex/agents/temper_implementer.toml) | `gpt-6.1-sol` | `high` | Accepted implementation, tests and ordinary debugging. |
| [temper_analyst](.codex/agents/temper_analyst.toml) | `gpt-6-astra` | `high` | Complex analysis, architecture and difficult failures. |
| [temper_reviewer](.codex/agents/temper_reviewer.toml) | `gpt-6.1-sol` | `high` | Separate final examination; never required review of its own implementation. |

The existing AGENTS.md restriction remains binding: do not spawn agents unless the user explicitly requests parallel agent work. This adoption does not supply standing authorization.
Default to serial delegation. Keep tiny or tightly coupled work with the lead.
No increased concurrency, recursive helpers or expanded native budget follows
from these roles; all stronger repository restrictions still apply.

When delegation is authorized, the lead supplies the issue/discussion, applicable
policy, accepted outcome and facts, relevant files/revision, acceptance, allowed
edits/ownership, checks, budget and stop conditions. Roles return concrete evidence
and actual limits. The lead owns tracker writes and integration and verifies
returned evidence; separate review does not grant independent assurance.

If Terra or its required tools are unavailable, only the lead may explicitly
select `temper_implementer` with Sol/high for that same bounded task and record
the fallback in the issue. The product role may not switch itself or delegate
its fallback. No fallback is selected for other unavailable routes; return the
missing choice to the lead/authorized decision maker. Never silently substitute
models or infer actual use from a model request.

Roles inherit parent permissions, sandbox/approvals and available tools; these
files grant no new tools, access, external writes or operational authority.
No `.codex/config.toml` defaults or concurrency changes are adopted, and this
selection does not change the primary chat model.

Where native named-role loading is unavailable, an equivalent runtime mapping
must use the exact instruction block from the corresponding linked role file
with its selected model/effort and a complete bounded brief, in fresh context if
settings require it. Validate that runtime mapping separately. Fresh role discovery
and actual model use remain
**unverified** until observed client/runtime metadata is recorded in the adoption
issue for each selected route. TOML parsing or a successful answer is not proof;
unobservable settings remain unverified. Do not claim cost or quality savings
without representative measured outcomes, including review and retry costs.

## Finite adoption authority and recovery

The owner's current adoption-only permission allows opening a **Draft** PR while
checks are incomplete. This permission covers only gonz0w/aegvium#129 and its
single adoption PR and expires on that PR's merge or abandonment, or on
abandonment of this adoption candidate if no PR can be opened.
This is a narrow exception to pre-publication check timing
for this maintenance outcome, not a check waiver: retain incomplete/blocked
results, signatures, DCO, protections, separate review and all required merge gates.
It grants no enduring bypass, product acceptance or expanded native authority.
Authorization to open a Draft does not authorize prohibited check execution or
other side effects; stop the affected publication if it would trigger them.

Routine accepted implementation/documentation and tracker activity retain only
the authority already defined by the linked policy and user task. Commit, push,
review, merge, release and operational actions remain distinct authorized steps;
this adoption does not grant merge or release permission. Existing product backlog
scope and identifiers remain canonical; the adoption issue records this maintenance
outcome without rewriting them.

Update or remove this selection only through the same authorized review process.
If adoption proves defective, revert the scoped adoption change through normal
signed review, preserving unrelated configuration, contracts and historical
receipts. Keep live failures, blockers and follow-up in the adoption issue.

## Artifact lifecycle

Apply the pinned [artifact lifecycle](.agent-temper/docs/reference/artifact-lifecycle.md)
and [local storage policy](docs/engineering/storage.md). Check capacity before
allocation, retain compact evidence, and reconcile owned temporary outputs on
every exit. Existing holds, cleanup approvals and native gates remain binding.
