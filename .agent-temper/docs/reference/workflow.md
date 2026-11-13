# Workflow

This reference expands the [core method](../../METHOD.md). A work item, review,
revision, and integration record are portable concepts. A project profile maps
them to actual tools and commands.

## Discover and decide

Understand the user, problem, intended outcome, constraints, and current system.
Read the selected work item and relevant discussion before changing artifacts.
For ambiguous work, ask focused questions and continue independent investigation.
Research has a question, a bounded investigation, and a decision or observation
as its deliverable. It does not automatically authorize implementation.

For an uncertain product request, identify the user's task and current workaround.
Separate observed evidence from assumptions. Compare plausible ways to address
the need and test the consequential unknown with a bounded investigation. Define
what would justify proceeding, revising, or stopping before observing the result.
Inconclusive or unavailable evidence does not establish success. Use authorized
sources and research methods; agent-generated scenarios are not user observations.
A well-understood fix can proceed with its existing acceptance and reproduction.

Create an implementation work item before implementing. A work item can contain
its specification, approach, and validation; do not create a parallel plan file.
Make a lasting interface or architecture decision a linked document when needed.

## Set milestones and slice work

Use these units without creating a separate document for each one:

| Unit | Boundary |
| --- | --- |
| Milestone | An observable capability, its exit conditions and its priority authority. |
| Issue or work item | One bounded contribution with assessable acceptance and an owner. |
| Delivery batch | A named outcome containing selected related issues, integrated and reviewed together. One issue can form a batch. |
| Attempt | A bounded implementation, investigation or verification effort with a result and a next-action rule. |

A milestone names an observable capability and its exit criteria. Group bounded
deliverables that establish that capability. Dependencies describe actual ordering
constraints. A calendar date or completed-task percentage does not prove readiness.

Plan the current increment in detail. Refine later work when its prerequisites are
known. Split by independently useful outcomes, ownership, contracts, or review
risk. Keep related positive and negative test cases within the same work item.
Do not divide work solely to meet a line, file, or ticket count.

The recorded priority authority selects milestone work and decides whether a new
finding displaces it. This role may be a person or an authorized agent. Recording
or refining an issue does not authorize implementation, change its priority or
place it in the active milestone. Keep proposed work in intake or backlog until
selected under project policy. Review discoveries at milestone planning and when
an actual blocker or the project's emergency criteria require an earlier decision.

For a new capability, specify one usable end-to-end task and its failure cases,
constraints, and affected interfaces. Keep the specification in the issue unless
a durable product contract needs a separate home. Derive checks from the agreed
behavior and examples, and reconcile implementation with that specification.

## Select ready work

Ready work has a clear outcome, non-goals, acceptance, verification, cleared
dependencies, and authority to proceed. A work item may be ready for research
while implementation is still blocked; name the permitted outcome explicitly.

Before starting a delivery batch, record its outcome, included issue identities,
exclusions, integration acceptance and lead in the authoritative work item or
review record. Link the member issues to that record; do not copy their live
status into another backlog. Include research or prerequisite work only when it
serves this bounded outcome. An entire milestone is not the default integration boundary.

By default, each integration lead owns one active delivery batch. Project policy
may select a different work-in-progress limit with a reason and clear ownership.
Count unfinished review and blocked work when making capacity visible. Another
agent's capacity does not authorize duplicate ownership or conflicting edits.

On a continuation request:

1. Read current project policy and the authoritative work record.
2. Inspect active changes and unresolved reviews before starting another change.
3. Select the highest-priority coherent ready item within the authorized scope.
4. Record ownership and the brief approach in that item.

At resumption, before expanding scope, and before integration, recheck the selected
issues, remaining acceptance, current ownership, evidence and next action. Continue
ready member issues within the batch without inventing a merge checkpoint for
each phase. Once the batch meets its integration acceptance, finish it before
pulling additional work. A changed batch needs an explicit membership/scope decision
under project policy, with its effect on acceptance, checks and effort recorded.

A blocked item names the blocker and what would remove it. Deferred work is not
current authorization. If no ready work is authorized, ask the owner to choose or
clarify it; do not invent a product direction.

Keep consumer constraints local. One project's executor, hosting, credentials or
integration blocker does not become a universal method prerequisite. Promote a
lesson into the framework only when it solves a portable problem with enough
value to justify its cost. Preserve the consumer's unmet acceptance separately;
independent framework work follows its own recorded priority and authority.

## Implement and coordinate

Inspect current source and relevant tests. Establish expected behavior before
changing it. Use the [verification reference](verification.md) for the change type.
Implement the smallest complete outcome and update affected documentation.

### Default development loop

Use the project's standing check map and authority. Keep the batch outcome,
included work, next development checkpoint, delivery gates and stopping boundary
in its existing owning work item; a small batch needs only a few lines.

1. Implement a coherent behavior slice across related files or ready member
   issues. An issue boundary alone does not require a new PR, full suite or review.
   Preserve required test-first reproduction before changing behavior.
2. At the slice's checkpoint, run the smallest checks that establish its changed
   contracts. Repair current acceptance defects within delegated scope. Record
   unrelated bugs and optimizations for milestone prioritization, then continue.
3. When the selected batch is complete, run its required delivery gates and obtain
   the separate final review. Continue ready member work without asking permission
   for each routine step already covered by the recorded authority.
4. Refresh checks and review for affected inputs or material findings. Once the
   batch is accepted, integrate and reconcile issues and milestone exit criteria.
   Do not add optional work to a finished delivery.

Project rules can require earlier checkpoints or stronger gates. A risky or
unknown impact can trigger checks immediately; this loop never postpones a
required check or authorizes an unselected issue. Use the
[verification cadence](verification.md#keep-feedback-fast-and-sufficient).

### Choose the work approach

For a clear, bounded change with known acceptance, proceed directly to the
affected source and checks. Investigate first when requirements, cause, impact
or an important design choice are uncertain. Missing authority still stops
dependent work. A failed attempt needs diagnosis before escalation or retry;
more reasoning or another agent does not renew the attempt limit.

These are work approaches, not model settings or different quality bars. Follow
the project's configured models, verification and separate-review requirements.
Keep tightly coupled implementation with one agent. Add specialist help when its
independent question or parallel scope justifies briefing, duplicated context
and integration costs; do not add a planner or router to every small task.

### Prepare relevant context

Read required instructions, applicable policy and the owning work item. Establish
the outcome, exclusions, acceptance, relevant source and check commands before
expanding the search. Use paths, symbols and scoped queries to find the needed
contracts; read surrounding code when a snippet could hide an invariant.
Load additional reference material to answer a concrete question.

A compact brief or summary may point to canonical sources; it cannot replace
required reading or override them. Reuse previously inspected material only
while its relevant source, policy and assumptions remain current. Recheck them
on resumption and after changed inputs. A context budget never removes an
applicable obligation. No repository index, memory service or context runtime
is required.

When orientation is difficult, use a small repository map that links key entry
points, data flow, invariants, external boundaries, tests, and maintained versus
generated files. Verify it by tracing one behavior and its affected consumers.
Link canonical commands and contracts; do not maintain an exhaustive file list or
live task state in the map. Record unavailable execution as a limit.

### Coordinate work and findings

One lead owns the integrated deliverable. Delegated work has an explicit boundary,
inputs, expected output, and verification. Inspect shared edits before overwriting
files. Separate working copies or nonoverlapping ownership can reduce collisions;
the method does not require a particular worktree tool or agent topology.

Batch independent reads when useful; keep dependent changes in order. Where the
client supports it, expose relevant tools and process mechanical intermediate
results before returning them to the agent. Return the facts needed for the
decision, actual outcomes, useful diagnostics and a source or evidence reference.
Keep full results available when review or recovery needs them. Make truncation,
failed reads and missing detail visible; a shortened result is not proof that
omitted checks passed. Do not add a model call merely to reformat structured data.

Stop owned delegated work when cancelled or complete, and reconcile any
pending effects. Preserve failures and distinguish assertion failures, timeouts,
and provider errors before deciding whether an authorized retry can help. This
adds no retry budget or authority. Use the
[workflow comparison procedure](verification.md#compare-agent-workflows) to assess
efficiency without removing required checks or review.

Resolve routine implementation choices under the project's delegation policy.
Stop affected work if policy is missing, conflicting, or requires an owner decision.
Do not use a timeout, silence, or another agent's preference as approval.

Give a discovery a disposition before implementing it:

| Finding | Action |
| --- | --- |
| Needed for current acceptance, including a defect introduced by the change | Repair within the selected scope and refresh affected checks. Split if it cannot remain bounded. |
| A genuine prerequisite prevents completion | Link the blocking work, record the sequencing decision and pause only dependent work. Do not silently absorb a separate outcome. |
| Unrelated bug, optimization or cleanup | Search for an existing issue; link it or create a bounded finding for later prioritization. Continue selected work. |
| Meets recorded emergency criteria | Use the project's emergency authority and record what work is displaced. Urgency alone grants no permission. |

A finding can remain in backlog with the missing reproduction or decision named;
do not run an open-ended investigation merely to make it ready. If acceptance
itself is wrong, explain the evidence and obtain the required authority before
changing it. Do not silently move the goalposts.

Use the [verification stopping rules](verification.md#bound-attempts-and-stop)
for investigations, costly checks and retries. If an implementation attempt
exceeds its recorded boundary, checkpoint and replan under the same authority;
do not quietly enlarge the batch or restart its budget.

## Manage generated output

Follow the project's [artifact lifecycle](artifact-lifecycle.md) before substantial
builds, experiments or downloads. Separate required evidence from rebuildable
intermediates, reuse verified inputs and keep caches within their recorded bounds.
At a delivery or handoff, record retained artifacts, holds and cleanup triggers
in the existing work item. Inspect active work and dependencies before authorized
cleanup; a size or age limit never grants deletion permission.

## Review and integrate

Create coherent changes with messages that explain the outcome and reference the
work item. Inspect the actual changed files, exclude unrelated work and private
data, and preserve meaningful history. Branch naming, commit syntax, signatures,
and merge strategy belong to the version-control/project profile.

Choose the integration boundary for coherence and reviewability. Multiple issues
may share one review when they contribute to that outcome. Sharing a milestone
or touching the same files alone is insufficient. Split for an independent
outcome, dependency/access boundary or material review/recovery risk; record why.
Do not delay a ready delivery to accumulate more issues.

The review record states the problem, resulting behavior, acceptance-to-evidence
mapping, consequential decisions, and remaining limits. Review current integrated
inputs and their affected consumers. If inputs change, refresh the relevant checks.
An agent review is a useful second examination, not proof of independent assurance.

### Review a correction

In the existing review record, link the prior reviewed candidate and what the
review covered. Give the current candidate, the changes since that review, the
disposition of each affected finding, and the affected contracts and callers.
Include relevant changes to the integration base, policy or environment. Link
the [fresh and retained check results](verification.md#reuse-evidence-after-a-change).
A small correction can use a few lines.

The separate reviewer checks the changes on the final candidate, the affected
contracts and callers, and any outstanding findings. Carry prior coverage only
where the recorded review still applies to the current inputs and project policy
permits reuse. Examine the rest of the required review scope directly. If the
prior review lacks a source identity or clear coverage, inspect the full scope
required by policy. Expand review and verification when a changed contract
affects more callers or when impact is uncertain.

Record the review decision for the final candidate, including coverage carried
forward, work examined in the follow-up, and any unresolved findings. Confirm
the current required gates before integration.

Integrate only within recorded authority and after the required checks and review.
Close implementation work only when its completion conditions are satisfied.
An unintegrated or abandoned change leaves unfinished work open. Reconcile linked
dependencies and parent outcomes; a merged component cannot establish untested
system acceptance.

## Release and operate

Use the project's explicit release and deployment authority. Identify the source
revision or revision set, built artifacts, supported targets, release notes, and
applicable qualification. Where behavior or data changes, provide compatibility,
migration, backup, rollback, and post-change verification appropriate to the risk.
Record unavailable checks and do not extend support claims beyond the evidence.

For an incident, follow the project's incident authority and containment/runbook
policy. Restore safe service, preserve useful evidence, and track corrective work.
An urgent action uses an explicitly authorized emergency path; urgency alone does
not grant new permissions. Remove secrets and personal data from public records.

Maintain dependencies and support policies through bounded updates. Deprecate or
remove interfaces only after checking users, communicated promises, and migration
needs. Use observed defects and review friction to improve the method itself.

## Maintain the repository and evaluate outcomes

A maintenance pass has an authorized trigger, a bounded set of records or checks,
and a completion condition. Inspect incoming reports, active reviews, failing
checks, blockers, and applicable dependency/support changes. Update existing work
or propose bounded findings in the tracker. Preserve ownership and distinguish
missing information from a defect. Age alone is not a reason to close an issue,
take over work, or rerun checks without investigating. Reconcile milestone exit
criteria against actual delivered evidence. Scheduling recurring work needs its
own authority; a maintenance guide does not enable an automation.

When usefulness needs evidence after delivery, record a success signal, evaluation
owner, and event or time that triggers a bounded follow-up. Use permitted feedback
or task observation; do not require telemetry for every product. Keep failed,
inconclusive, and unavailable observations distinct. Record the decision to retain,
revise, stop, or investigate further under project authority. Close implementation
at its accepted boundary and track separate later learning in linked work. If
outcome evidence is part of current acceptance, keep that gate in effect. Do not
silently extend completed acceptance or infer product success from a passing test suite.

## Leave a usable continuation

Keep a compact checkpoint in the work item when work is interrupted or handed off:

- Current source revision or working-change identity and review link.
- What has been completed, with actual verification and its scope.
- What remains, including a named blocker or unresolved decision.
- The next concrete action and any authority needed for it.

Do not paste a full conversation or maintain a second status journal. A new agent
must recheck current state; the checkpoint is evidence and orientation, not a
guarantee that source, permissions, or external systems remain unchanged.
