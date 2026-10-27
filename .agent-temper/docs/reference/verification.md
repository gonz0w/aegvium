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

Run focused checks during iteration, then the required checks for changed contracts
and their consumers before integration. Use broader platform, security, recovery,
and release checks when the change or project policy requires them. Unknown impact
is a reason to investigate or broaden checks, not to assume no impact.

Document a stable local check entry point. CI should call the same maintained
commands where practical. Optional hooks are convenience checks; a bypassable hook
is not integration enforcement. Formatting, static analysis, linting, secrets,
dependency provenance, and license checks are selected for the project's actual
stack and risk. Avoid importing a large tool suite without a demonstrated need.

Do not rerun unchanged expensive checks merely because a new review record exists.
Evidence reuse needs the same relevant inputs, environment assumptions, and valid
scope. Changes to contracts, validation policy, fixtures, or relevant dependencies
can invalidate it. Required CI policies still apply to the current proposed change.

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

Historical evidence remains tied to the bytes and conditions actually measured.
Keep those inputs resolvable through retained source revisions or artifacts before
changing them. Do not rewrite old results to describe current code. Do not require
duplicate source archives when existing retention already preserves the inputs.

## Review the result

Review acceptance, tests, implementation, documentation, dependencies, and applicable
security/recovery effects together. Use a separate reviewer for consequential work
as required by project policy. Record whether review was author, peer-agent, human,
or specialist; do not turn a label into a stronger assurance claim.

Automated gates can detect missing structure and run assertions. They cannot prove
that every requirement is correct, every reported run occurred, or every important
failure was tested. Inspect the actual evidence and final diff. A project must
name who may accept unresolved gaps and what cannot be waived.
