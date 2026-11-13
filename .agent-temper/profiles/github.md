# GitHub work profile

This profile maps the [method](../METHOD.md) to GitHub. It supplements the
[workflow](../docs/reference/workflow.md) and
[verification policy](../docs/reference/verification.md). It does not grant
permissions or require Git for projects that use another work profile.

## One work authority

GitHub Issues are the sole authority for live work, priority, dependencies,
ownership, and continuation. GitHub Projects may display those issues; avoid
separate status fields that conflict with the canonical issue state. Repository
documents hold durable contracts and decisions, not duplicate backlogs.

Read an issue and its comments before implementation. Create a finite issue when
authorized work has no issue. An epic provides context; implement its bounded
child issues. Each executable issue names a useful deliverable, scope and
non-goals, acceptance conditions, expected verification, and real prerequisites.
Keep related test cases together. Do not make a separate issue for each assertion
or mechanical substep.

Use milestones for capabilities with explicit exit conditions. Keep distant work
coarse until prerequisites make a useful assignment possible. An issue belongs
to a milestone only when it contributes to that capability.

## State, dependencies, and ownership

Each open executable issue has exactly one progress label. The following names
are defaults. A project may record a complete one-to-one mapping from these states
to equivalent local labels: one label per state, with no label used for two states.
Keep the meanings, readiness conditions, and closure rules intact. Without a local
mapping, use these defaults.

| Label | Meaning |
| --- | --- |
| `status:backlog` | Work that does not yet meet the project's start conditions. |
| `status:deferred` | Work explicitly deferred and not authorized within the current scope. |
| `status:ready` | Bounded, authorized, understood, and unblocked. |
| `status:in-progress` | An identified agent or person is implementing it. |
| `status:blocked` | A named dependency or decision prevents progress. |
| `status:review` | Implementation is ready for its required review. |

For example, `status:needs-triage` may map to the backlog state. Record all other
state mappings too, even when their names stay the same. Adoption does not silently
relabel existing issues; review any required transition under project authority.
An ambiguous or conflicting mapping blocks affected work until resolved through
[the extension policy](../docs/reference/extensions.md).

Closed issues use GitHub's closure state and have no active progress label.
Document closure reason; “not planned” is different from completed. Epics are
identified as coordination issues and use child completion and exit conditions,
not a misleading implementation state.

The project records its priority convention and milestone order. Use a concrete
blocking relationship where supported, or an explicit `Blocked by #NUMBER`
reference in the issue. Links alone do not establish a dependency. Name the
current owner in the assignee field where possible; record agent ownership in a
comment when no assignable identity exists. Check for active owners and reviews
before starting concurrent work.

## Starting and resuming

1. Read project policy, the current milestone, assigned active work, and open
   reviews. Inspect the actual source and review state before assuming progress.
2. Resume authorized active work or address its review feedback. Do not duplicate
   another owner's work or silently take it over.
3. Otherwise select the highest-priority ready, unblocked issue under the
   project's selection rules. Ask when a consequential priority conflict has no
   recorded resolution. If no work is ready, report the blocker or propose a
   bounded issue within the project's authority.
4. Read the entire selected issue and discussion, claim ownership, and record a
   concise implementation and verification approach before changing behavior.

Use issue comments for discoveries and meaningful progress. A continuation
comment identifies the revision or branch, completed acceptance, actual checks,
remaining work, blockers, and next action. Do not add a comment for every command.
Keep sensitive evidence outside public issues and link only approved material.

## Maintenance passes

Bound a pass by its trigger, issue/PR scope, and completion condition in an issue.
Search existing reports before adding one. Link duplicates to the canonical issue
and preserve unique reproduction details; use the project's authorized closure
reason and remove active progress labels from closed issues. An unclear report
stays in backlog with the missing information named, not ready by default.

Inspect the exact failing check and revision before classifying a code defect,
environment failure, or unavailable service. Preserve failed evidence; a retry
does not explain an intermittent failure. For a stalled PR, inspect outstanding
reviews and ownership before proposing its next action. Do not infer abandonment
from age. When a dependency closes, recheck the blocked issue's full readiness.

Dependency/support findings become bounded work under existing priority and scope
authority. Reconcile milestone exit conditions from delivered evidence, not issue
counts. A completed pass records findings, existing or new issue links, unresolved
limits, and next owners; it does not require every discovered defect to be fixed.

## Reviews and completion

Map a delivery batch to one coherent PR. Record the selected issues, outcome,
exclusions, lead and integration acceptance in its description or a linked owning
issue before implementation. Keep issue-level acceptance at its canonical home.
Follow the [batch and discovery rules](../docs/reference/workflow.md#select-ready-work)
and the project's work-in-progress limit. Do not make a PR for every test or phase,
or leave a complete PR open while adding optional work. New findings stay in
backlog until selected by the recorded milestone priority authority.

Open a pull request against the project's recorded integration branch when GitHub
hosts the source and PRs are the chosen integration mechanism. Give reviewers the
problem, resulting behavior, acceptance mapping, actual verification, and material
limitations. Include required reproduction or test-first evidence. A checklist
alone does not prove execution.

Use one real `Closes #NUMBER` line for each executable implementation issue whose
entire acceptance is satisfied by the change. Do not use closing keywords for
epics, partially completed issues, or work requiring separate operational
acceptance. Split unrelated or independently deliverable discoveries into bounded
issues before implementing them. Do not remove acceptance merely to finish.

When using pull requests, completed implementation issues close on merge, not
when a PR opens. GitHub
automatically processes closing references only under its supported default-branch
rules; if the recorded integration branch differs, reconcile closure after the
accepted merge. Abandoned or unmerged PRs leave implementation issues open.
If source uses another integration mechanism, record the accepted source revision
and close implementation work only after its recorded integration acceptance.
Research and coordination issues close when their recorded exit conditions are
met and their required review is complete; they need not invent a code PR.

Integration, release publication, and production acceptance are separate decisions.
Use linked bounded work when delivery needs a later release or operational gate.
After integration, reconcile issue labels, dependent readiness, and parent
milestone or epic exit conditions. Follow the project policy for who may merge,
close coordination work, or publish a release.
