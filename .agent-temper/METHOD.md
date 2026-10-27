# The Agent Temper method

Deliver a useful outcome with the smallest understandable change, and provide
evidence that it works. Optimize the whole experience: implementation, review,
operation, maintenance, and the documents a person reads.

## Apply the rules deliberately

**Must** identifies a requirement of this method. **Should** identifies a default
that permits a recorded, scoped reason to use another approach. **When** makes a
rule conditional. A project records its adopted revision, applicable profiles,
choices, and exceptions. Only explicitly selected profiles apply; a file in the
bundle does not activate itself. Adoption never grants permission to act.

Platform instructions, access controls, and the owner's actual authority still
apply. A work item defines a task; it cannot silently override project policy.
An explicit authorized decision can change policy, but the agent must record the
change and its effect. If applicable rules conflict, stop dependent work and ask.

## The core requirements

1. **Keep one authority for live work.** Work items own scope, priority, dependency,
   progress, and continuation. Product documents describe behavior. Decisions
   explain choices. Evidence records describe observations. Secondary views must
   be derived from, or link to, the authoritative tracker.
2. **Make work finite.** Before implementation, identify the outcome, non-goals,
   acceptance, dependencies, verification, and owner. A broad milestone is context;
   select a bounded deliverable. Do not extend finished acceptance with upgrades.
3. **Resolve project policy once.** Ask the owner about a missing or conflicting
   required decision before affected work. Record the answer. Apply it in later
   sessions without asking again. Change it only through an explicit authorized
   decision. Delegate routine implementation choices in that same policy.
4. **Specify observable behavior.** Establish expected results and failure cases
   before implementation. Prefer test-first behavior changes. Reproduce defects
   before fixing them, or record why a deterministic reproduction is unavailable
   and what alternative evidence will establish the result.
5. **Choose the simplest suitable implementation.** Meet current requirements and
   necessary safety, recovery, accessibility, and compatibility constraints. New
   languages, services, dependencies, abstractions, and options need a present
   benefit that justifies their full maintenance cost.
6. **Verify honestly.** Use meaningful checks of the affected contracts. Keep
   passed, failed, skipped, unavailable, and not-applicable results distinct.
   Never invent execution, weaken an expectation to hide a defect, or describe
   historical results as fresh tests.
7. **Deliver for people.** Update the affected user instructions, reference, and
   examples with the behavior. Keep changes readable, explain consequential
   choices, and provide setup, recovery, and support limits where relevant.
8. **Finish and reconcile.** Review the integrated result, satisfy the applicable
   gates, and update the work record. Integration, release, deployment, and
   operational acceptance are separate events when the project distinguishes them.

## Decide locally

The project must record its purpose and constraints, work authority, technology
and support scope, verification commands, documentation conventions, and authority
for review, integration, release, and consequential external actions. Record
license and dependency policy where material. An explicit "not applicable" needs
a reason; an empty field is not consent.

Projects may strengthen requirements. A departure from a core requirement must be
visible as a deviation; do not claim full method conformance for that scope. A
default can be replaced with a justified project choice. New upstream guidance
does not change a pinned project policy until the project adopts it.

## Keep the method small

Use the issue itself for small specifications and approaches. Add a separate design
or decision record when a lasting contract, costly tradeoff, or cross-component
change needs explanation. A test scenario rarely needs its own issue. A short
fix rarely needs a design document. Do not add a process merely because another
team has one.

Prefer the established stack in an existing project. For a new project, choose
technology against the actual platform, ecosystem, deployment, and maintenance
needs. Count transitive dependencies and operational work. Fewer dependencies
does not justify replacing mature security primitives with unreviewed custom code.

Before a substantial change, explain the simpler alternative and why the chosen
approach is appropriate. Remove obsolete complexity only within agreed scope,
after checking its users and recovery implications.

## Use the supporting references

- [Workflow](docs/reference/workflow.md): discovery through maintenance and continuation.
- [Verification](docs/reference/verification.md): test selection, evidence, and review.
- [Documentation](docs/reference/documentation.md): structure and clear writing for readers.
- [Profiles and extensions](docs/reference/extensions.md): compose rules and feed adoption findings back.
- [GitHub profile](profiles/github.md): the first concrete mapping of portable concepts.
- [Strict test-first profile](profiles/strict-test-first.md): an optional stronger verification practice.
