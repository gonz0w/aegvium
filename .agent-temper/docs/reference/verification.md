# Verification and evidence

Verification connects the agreed outcome to observable results. Follow the
[core method](../../METHOD.md) and the project's declared checks. A successful
command is evidence only for what it actually exercised.

## Choose checks by change and consequence

| Change | Expected approach |
| --- | --- |
| Defect | Reproduce expected versus actual behavior. Add a regression that fails for the defect and passes with the fix. |
| New behavior | Define success, rejection, and failure cases first. Prefer red, green, then refactor. |
| Refactoring | Establish relevant existing behavior, add missing characterization where useful, and preserve it. |
| UI or interaction | Exercise real interactions and inspect rendered output, usability, accessibility, and applicable fallbacks. |
| Storage or protocols | Test compatibility, malformed inputs, boundaries, failure, recovery, and affected consumers. |
| Configuration or CI | Check observable behavior in a suitable fixture; syntax alone may be insufficient. |
| Documentation | Check accuracy, links, examples, command results, navigation, and relevant rendering. |
| Research | Define the question and decision criteria; preserve observations, failed candidates, and limits. Prototype code still needs appropriate behavior checks. |

Tests derive expectations from the requirement, independent examples, or stable
contracts. Assertions that duplicate the implementation can repeat its mistake.
Use the cheapest layer that provides the needed evidence, and add integration or
real-system checks where mocks cannot establish the contract.

## Use test-first work honestly

For red, run the relevant test before implementing the behavior and record the
actual expected failure. An unrelated setup failure does not reproduce a bug.
A missing-module failure can establish a new interface's absence; it must be
followed by substantive positive and negative behavior tests.

For green, implement the narrow change and run the relevant checks. For refactoring,
keep expectations intact and check affected behavior again. If no cleanup is useful,
say so. Never claim a failing run that did not happen.

When test-first execution is unsuitable, record the reason and alternative evidence
before relying on that exception. For intermittent or unavailable environments,
describe what is known, what the available checks establish, and what remains
unverified. Do not call inaccessible verification a pass. A project may require a
stricter test-first policy for particular changes.

## Keep feedback fast and sufficient

Choose checkpoints by coherent behavior and consequence. A development window can
cover several related files or ready member issues before its focused checks.
Do not automatically run the full suite after every save, commit or issue. A
project's stricter test-first or earlier-check requirement still applies.

| Boundary | Default check cadence |
| --- | --- |
| Before a behavior change | Specify expected results and run the required reproduction or test-first RED. |
| During a coherent implementation slice | Develop the related change; check immediately if policy, uncertainty or new risk requires it. |
| At its development checkpoint | Run focused changed-contract checks; inspect failures before further work. |
| At the assembled delivery boundary | Run all applicable required integration gates and obtain separate final review. |
| After a correction or changed input | Refresh affected checks and review; reuse unaffected evidence only within its valid scope and required CI policy. |
| At milestone reconciliation | Assess delivered capability and outstanding findings; select later work instead of accumulating optional checks. |

Use broader platform, security, recovery and release checks when the changed
contracts or project policy require them. Unknown impact is a reason to investigate
or broaden checks, not to assume no impact. A successful focused checkpoint alone
does not establish integration or operational acceptance.

Document a stable local check entry point. CI should call the same maintained
commands where practical. Optional hooks are convenience checks; a bypassable hook
is not integration enforcement. Formatting, static analysis, linting, secrets,
dependency provenance, and license checks are selected for the project's actual
stack and risk. Avoid importing a large tool suite without a demonstrated need.

### Reuse evidence after a change

1. Compare the current candidate with the one checked. For each result you plan to
   carry forward, use the check contract to confirm its relevant inputs,
   environment assumptions, and scope still match. Include shared contracts,
   fixtures, dependencies, and verification policy. If impact is uncertain,
   investigate or refresh the check.
2. Refresh affected checks and send material changes in scope or evidence back to
   the reviewer. In the existing batch record, link each retained result and
   explain why it still applies. Identify the results from fresh execution.
3. Read the required gates for the current candidate in the integration system.
   Where it records command results and job conclusions separately, record both.
   Passing commands can coexist with a failed or unavailable required job.

If a required job is interrupted, reconcile the previous attempt's effects before
retrying within its recorded allowance. Rerun that job alone when project policy
permits it and the integration system still accepts the other successful gates
for the current candidate. Confirm the new required result and retain the
original failure. Use the project's required check set when partial execution
is insufficient.

## Bound attempts and stop

Before an investigation, costly verification campaign or retry sequence, record
the question or acceptance/risk it addresses, identified inputs, applicable checks,
permitted executor, effort/resource limit and next-action rule in the work item.
Reference existing project policy instead of repeating it. A routine focused
check can be one run followed by inspection of any failure; it needs no separate
plan or arbitrary universal time allowance. A larger campaign needs a finite
budget appropriate to the project and its execution authority.

Use these outcomes:

| Outcome | Next action |
| --- | --- |
| Acceptance evidence is sufficient, required checks pass and review is resolved | Finish the selected integration under its authority. Extra polish or unrelated hardening becomes proposed work. |
| A check exposes a current acceptance defect | Repair within the selected scope and limit, then rerun affected checks. |
| A new relevant risk or changed input invalidates the planned coverage | Explain the gap and amend the checks and effort under recorded authority. Preserve required gates. |
| The limit is reached, a required executor is unavailable, or failure repeats without new information | Preserve the result, checkpoint and report the blocker or replan. Continue only independent authorized work. |

Budgets do not grant execution permission or waive failed/unavailable checks.
Do not renew an attempt automatically, retry an uncertain external effect without
reconciliation, or treat a tool error as evidence of a product defect. Record
what changed and why another authorized attempt can answer the question.

Source integration, native qualification, release and operational acceptance may
have different evidence boundaries only when project policy defines them.
Do not move an unmet condition into later work merely to close an issue. A
broader gate remains binding where it is required, even when focused checks pass.

## Record enough evidence

Record the command or procedure, result, relevant source/input identity, environment,
and material limitations. Keep useful failure output and reproduction details. Use
compact records for ordinary work; stronger support or security claims can require
more durable artifacts. Protect private data, credentials, and sensitive findings.

| Result | Meaning |
| --- | --- |
| Passed | The stated check executed and its assertions succeeded. |
| Failed | The check executed and detected an unmet expectation. |
| Skipped | An applicable check was deliberately not executed; state why. |
| Unavailable | The environment, permissions, or infrastructure prevented the check. |
| Not applicable | The check does not apply to this change; explain the boundary. |

Zero discovered tests are not a passing test suite. A timeout or infrastructure
error is not an assertion result. Source hashes establish identity; they do not
prove correctness. A check of a saved report does not rerun the product test.

For ordinary work, a compact acceptance-to-result record is sufficient. Link the
standing command contract and retained output; do not copy the full policy, log
or previous review into every checkpoint. Stronger traceability can be required by
the project's risk and evidence policy. This changes reporting cost, not truth.

Historical evidence remains tied to the bytes and conditions actually measured.
Keep those inputs resolvable through retained source revisions or artifacts before
changing them. Do not rewrite old results to describe current code. Do not require
duplicate source archives when existing retention already preserves the inputs.
Keep retained evidence separate from rebuildable output and apply the project's
[artifact lifecycle](artifact-lifecycle.md). Retention limits never remove an unmet
review, reproduction, incident or recovery need without its authorized disposition.

## Compare agent workflows

Before observing results, record the comparison question, current baseline,
candidate, representative task groups, and decision rule in the work item. Group
work by relevant difficulty and risk. Fix the quality bar first: required outcomes,
known defects that must be detected, acceptable false positives, severity accuracy
where relevant, and allowed review corrections. Use separately checked expected
results; record gaps in that reference. Decide what improvement would justify a
change while preserving required quality, checks, and review.

Before model execution, have a reviewer independent of the evaluated worker
examine its complete visible inputs for answers: instructions, policy overlays,
examples, tests and later source can expose an expected result. Record the input
identities, permitted reference material and separation limits. Preserve required
policy reading. If necessary material exposes the answer, choose another case or
classify the case as development or feasibility work. This review can find
leakage; it does not guarantee independence.

If exposure is discovered after execution, retain the runs and their costs and
exclude them from held-out evaluation support. Do not silently replace them or
renew the trial budget. New inputs need a reviewed scope and budget decision
under the project's authority.

**Fictional example:** A policy overlay includes the corrected document used in a
historical repair task. Before spending the trial budget, a separate reviewer
classifies that task as development evidence. The lead selects a different
evaluation case under the recorded scope and budget.

Compare matched inputs under recorded conditions. Identify task and source
revisions, requested and observed model/effort, client, tools, environment, and
resource bounds. Keep tuning examples separate from evaluation where practical.
Repeat or vary execution order when needed to assess noise, cache effects, and
sample limits. Record differences that prevent a fair comparison. A small sample
can support a bounded trial; it does not establish a universal ranking.

Measure the whole task through acceptance, including the lead, delegates, context
and available input/output/cache token usage, tool calls, retries, coordination,
validation, review, repair, and elapsed time. Preserve failed and cancelled attempts.
Calculate cost per accepted outcome as total measured cost, including rejected
work, divided by accepted outcomes. With no accepted outcomes, that ratio is
undefined. Unavailable usage or prices are not zero: report the gap and avoid a
monetary savings claim that depends on it. Keep elapsed time separate from summed
agent effort, particularly when work overlaps.

Preserve each provider's usage definitions. Cached input is often a subset of
input, and reasoning usage may be included in output; do not count a subset twice.
Separate measured API charges, subscription usage limits and local operating
costs. Fewer tokens or a higher cache-hit rate does not by itself establish a
lower bill. Include setup and maintenance when comparing an optional local model
or harness. Record unavailable measures instead of estimating them as observations.

Check validated findings, missed known defects, false positives, severity accuracy,
and review corrections alongside acceptance. More findings can mean more noise;
fewer can mean missed defects. Agent agreement can share a mistake. An author's
edit does not establish that a finding was correct. Model judges can help triage,
but their errors and limited inputs need separate examination. Check missed
required behavior as well as the findings that were reported.

Record the decision to retain, change, or investigate, with evidence and limits.
Apply the [evidence-reuse rules](#keep-feedback-fast-and-sufficient) when inputs
stay relevant. A favorable comparison does not waive policy or silently change
model defaults. Optional routing uses the
[Codex profile's runtime checks](../../profiles/codex.md#verify-use-and-evaluate-benefit).

### Fictional comparison

All measurements below are synthetic. A fictional project compares two candidates
with its baseline on ten matched review tasks, with two planted defects per task.
Before running, it requires all 20 known defects, correct severity for each,
at most two validated false positives, no outstanding review corrections, and ten
accepted tasks. Among candidates meeting that bar, it selects lower total cost.
Costs include lead/delegated work, failed attempts, review, and repair for all ten
tasks. Time is elapsed time for each complete batch under the same conditions.

| Workflow | Known defects found | False positives | Accepted tasks | Total cost | Cost per accepted task | Elapsed minutes | Decision |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Baseline | 20/20 | 1 | 10 | $10.00 | $1.00 | 100 | Reference |
| Candidate A | 20/20 | 1 | 10 | $8.00 | $0.80 | 80 | Accept for this bounded trial |
| Candidate B | 18/20 | 0 | 8 | $5.00 | $0.625 | 60 | Reject: two tasks each miss one required defect |

All detected defects have correct severity; accepted tasks have no outstanding
review corrections. Candidate A saves 20% in this fictional batch. Candidate B's
ratio includes the cost of its two rejected tasks, but lower cost cannot satisfy
the missing quality requirement. Planted defects and this small sample do not
establish coverage of unknown defects or measured Temper benefits.

The [Cloudflare optimization case study](https://blog.cloudflare.com/obsessive-inference-optimization/)
reports cost improvements and lost useful findings in some lower-effort reviews.
It also describes limits in its overall cost attribution and quality measures.
Use such observations to choose questions to test, rather than transfer reported
gains to a different workflow.

## Review the result

Review acceptance, tests, implementation, documentation, dependencies, and applicable
security/recovery effects together. Use a separate reviewer for consequential work
as required by project policy. Record whether review was author, peer-agent, human,
or specialist; do not turn a label into a stronger assurance claim.

Automated gates can detect missing structure and run assertions. They cannot prove
that every requirement is correct, every reported run occurred, or every important
failure was tested. Inspect the actual evidence and final diff. A project must
name who may accept unresolved gaps and what cannot be waived.
