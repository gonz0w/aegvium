# Strict test-first work

Select this optional practice profile when a project requires an observed failing
test before behavior changes. It strengthens the default in
[verification and evidence](../docs/reference/verification.md). Selection must be
recorded in project policy; copying this file does not activate it.

## Applicability and compatibility

Apply this profile to new or changed behavior, defect fixes, executable test/check
tooling, service configuration, and CI behavior. For pure refactoring, establish
the relevant existing behavior first and add missing characterization tests before
changing implementation. Do not manufacture a failing test for unchanged behavior.

The profile is compatible with the [method](../METHOD.md) and with tool profiles
that retain its evidence requirements. Keep stronger project rules, security
checks, environment requirements, and review gates in effect. Resolve conflicting
rules through [the extension policy](../docs/reference/extensions.md) before
dependent work. This profile grants no authority to change or integrate software.

## Red, green, and refactor

1. Define acceptance and meaningful success, rejection, and failure cases before
   implementation. Derive expectations from the requirement or a stable contract.
2. Run the relevant test against the old behavior. Record the command or procedure,
   source/input identity, expected failure, and actual result. A defect test must
   expose the defect; an unrelated setup failure does not reproduce it. A missing
   module may demonstrate a new interface's absence, followed by substantive
   positive and negative contract tests.
3. Implement the smallest complete change. Run the focused checks and the project's
   required checks; record their actual results and limitations.
4. Refactor when useful, preserving assertions and checking affected behavior
   again. If no refactoring is needed, say so. Map acceptance to the resulting
   evidence in the review record.

Do not invent a retrospective red run or weaken tests to obtain green. Test and
review the actual composed result, including affected consumers, using the
project's required verification layers.

## Prose, research, and unavailable checks

Documentation-only and research-only prose use appropriate source, policy, link,
example, and reader validation. Prototype code and executable examples still have
behavior that needs the applicable tests. Calling a change research does not
exempt executable changes from this profile.

When a required failing reproduction or check cannot be performed, record the
reason, available evidence, and remaining gap. An exception requires the project's
explicit authorized decision before relying on an alternative; the implementing
agent cannot silently downgrade this requirement. Existing stronger exception
limits remain binding. Report unavailable checks as unavailable, never as passed.

Automated metadata checks can verify required fields. Reviewers must still inspect
the test, observed failure, resulting behavior, and evidence. Neither this profile
nor a completed checklist proves that a reported command ran.
