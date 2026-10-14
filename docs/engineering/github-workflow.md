# GitHub work and acceptance workflow

Aegvium uses one private [Project](https://github.com/users/gonz0w/projects/5) and [repository](https://github.com/gonz0w/aegvium). Git owns PRD/EDD/Test Design, contracts, ADRs and source-bound evidence. GitHub owns live status, priority and native dependencies. No repository split or product implementation is approved by backlog creation.

## Work items and labels

Use one bounded issue per observable outcome, in its owning repository. Use the
work-item or bug form. Every issue body has these sections, including backfills:

1. Outcome: the result and its scope.
2. Acceptance: observable checklist criteria, including required evidence.
3. Design and requirements: requirement IDs and authoritative Git links.
4. Relationships: parent acceptance gate and blockers.
5. Existing evidence: merged PRs and exact candidate-specific receipts, or explicit gaps.
6. Tracking scope: boundaries, limitations and remaining work.

Exactly one `status:` label mirrors Project Status. Choose one primary kind:
`type:feature`, `type:research`, `type:acceptance`, `type:tracking` or
`type:documentation`. Preserve useful labels such as `bug` and `accessibility`.
Use exactly one `priority:P0`, `priority:P1` or `priority:P2`. P0 is critical
correctness/security/recovery or a blocking qualification failure; P1 is current
phase work; P2 is later or lower-priority work. A future feature is a planning
outcome until it is split into reviewed implementation slices when picked up.
Migration does not approve future product implementation.

| Status label | Project Status | Meaning |
|---|---|---|
| status:backlog | Backlog | Awaiting scoped design, prerequisite or triage. |
| status:ready | Ready | Bounded, authorized, specified and unblocked for pickup. |
| status:in-progress | In progress | Active owned work. |
| status:review | Review | Reviewable PR or design awaits maintainer review. |
| status:validation | Validation | Evidence/acceptance remains, including unresolved failures. |
| status:done | Done | Every scoped criterion satisfied; issue closed as completed. |

Blocked work stays open. Native blocked-by links identify prerequisites;
readiness is not inferred from a label alone. A Ready item that acquires an open
blocker returns to Backlog or Validation as appropriate. Duplicate/cancelled work
must link its replacement or decision; do not label an unsatisfied outcome Done
or include it as completed evidence. Remove cancelled items from the completed
queue, preserving the issue's history and useful labels.

## Phase gates and relationships

Use matching repository milestones for M0, M1, M2, M3, M4, M5 and Later with no
invented dates. Phase mirrors the milestone. Native sub-issues link owned outcomes
to their coordinating gate. Use native blocked-by relationships as well as body
links; body text alone is not the dependency graph. A gate depends on its owned
outcomes and preceding capability gate. This expresses acceptance without
assuming native operations or daemon publication are atomic.

A sub-issue has one parent. BootWeave producer work and Arxwall integration work remain in their own acceptance trees. Aegvium consumes their reviewed contracts through links and external blockers when those trackers are identified; do not invent or duplicate external work. No specific external issue is assumed available at setup.

## Pickup and acceptance

Inspect open PRs and unblocked Ready work before continuing. Read linked requirements and reviewed scoped design or explicit research authorization. Update one status label and Project Status at pickup, review and acceptance. Use codex/ branches, signed Conventional Commits and matching author DCO. Follow [local review](review.md). Leave PRs open for Cam.

Component closure requires merged scoped implementation/docs plus its evidence. Use Refs for phase gates and partial outcomes; Closes only when merge satisfies every criterion. Native support, complete CRS enforcement, recovery, resource limits, seven-day soak, BootWeave installation and personal-use acceptance remain distinct. Preserve original failed/skipped receipts and separate later analysis/repeats.

## Project and manual triage

Status: Backlog, Ready, In progress, Review, Validation, Done. Phase: M0–M5 and Later. Priority: P0/P1/P2. Keep fields, exactly one status/priority label, milestone, issue state, parent and blockers consistent. Ready means authorized and no open blocker. Gates stay open until explicit candidate-specific acceptance; no dates promised. See [stable index](../milestones/github-roadmap-index.md).

Views copied from Nomvium: All work (table, is:issue), Current M1 (board, phase:M1 is:open), Ready next (status:Ready is:open), Acceptance gates (tracking/acceptance), Completed evidence (closed Done). Update current-phase filter on acceptance. Automatic status/closure workflows are disabled; free built-in sub-issue discovery may add items but never accepts evidence. No Actions, paid automation, remote status publisher or ongoing external synchronizer.

## Recoverable setup

Initial issue bodies carry stable aegvium-roadmap markers. An ignored .tools setup journal stores IDs and sanitized read-backs. Reuse existing IDs and inspect every pagination page before retries; reject duplicate markers. Native sub-issues and blocked-by links are authoritative relationships, body links help readers. Never replay an old setup plan over human triage or duplicate/reparent other projects' work.

## Outcome batching

Before creating a work item, inspect existing outcomes and open PRs. Reuse an existing issue with acceptance subchecks for related experiments, fixes, native repeats and evidence. Create a new issue only for a distinct deliverable or an independently actionable blocker; phase gates and outcome trackers must not duplicate experiment tasks.

Keep scoped design, implementation, meaningful tests, native execution, failure correction and final findings on one codex/ branch and PR until the agreed outcome is reviewable. A continue turn or individual experiment is not a PR boundary. Related source-build qualification belongs with the fixture it qualifies when review is still open. Do not create preparation-only or tracking-only PRs for routine follow-up; include those updates in the substantive outcome.

Define the decision or capability the batch establishes and the concrete remaining blockers. Native failures remain immutable evidence; corrections and reruns stay on the same PR without weaker acceptance or a claim that research authorizes runtime adoption. Split a batch when it introduces a separate architecture decision, independently reviewable deliverable, dependency/approval boundary or excessive review complexity. Keep source-bound receipts for each signed candidate inside the batch.
