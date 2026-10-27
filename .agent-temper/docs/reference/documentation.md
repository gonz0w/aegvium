# Documentation standard

Documentation helps a person understand a product, complete a task, or make a
decision. Agent-written output must meet the same standard as reviewed human
work: accurate, useful, navigable, and proportionate to the task.

## Organize around a reader need

Use the four reader needs described by [Diátaxis](https://diataxis.fr/):

| Reader wants to… | Form | Include |
| --- | --- | --- |
| Learn through a safe example | Tutorial | A starting point, guided practice, and a visible result |
| Complete a specific task | How-to guide | Prerequisites, ordered actions, checks, and relevant recovery |
| Look up a fact or contract | Reference | Precise behavior, interfaces, limits, and supported values |
| Understand a choice or concept | Explanation | Context, reasoning, alternatives, and tradeoffs |

Give each page one main purpose. Link to related information instead of mixing
an installation procedure with a long design discussion. Create sections when
readers need them; do not create empty directories to complete a diagram.

## Give each fact one home

| Artifact | Responsibility |
| --- | --- |
| README | Purpose, maturity, supported scope, quickstart, checks, and navigation |
| Agent entry point | The adopted method, local policy, work authority, and essential commands |
| Project policy | Approved project decisions, extensions, exceptions, and decision authority |
| Contribution guide | How to propose, verify, review, and deliver a change |
| Product and technical docs | Current behavior, contracts, operation, and architecture |
| Decision record | A consequential choice, its reasons, and any explicit supersession |
| Work tracker | Priorities, dependencies, active work, evidence, and continuation |

Link to the authoritative fact. Do not maintain another backlog in a README or
agent memory file. A historical report may describe completed work; label its
date, source revision, and limits so readers cannot mistake it for current policy.

## Write procedures in clear English

Agent Temper uses an original, STE-informed plain-English style.
[ASD-STE100](https://www.asd-ste100.org/about_STE.html) is a controlled language
with writing rules and a dictionary. This repository does not reproduce that
standard or claim formal compliance. Its writing guidance is not a substitute
for the standard when a project requires conformance.

- State the result and prerequisites before the procedure.
- Start each numbered step with an action. Keep each step focused on one action
  or a small action and its immediate check.
- Put a condition before the action it controls: “If the check fails, restore
  the saved configuration.”
- Name the actor and object when they could be confused. Prefer “The operator
  restarts the service” to “It should then be restarted.”
- Use a consistent name for each concept. Define unfamiliar terms at first use.
- Give the expected result at useful checkpoints. Distinguish sample output
  from observations made during validation.
- State the working directory, required tools, inputs, and relevant effects of
  commands. Keep commands copyable; exclude prompt characters.
- Describe meaningful failure recovery. Put a warning immediately before the
  action with the consequence, when that consequence is material.

Use short sentences where they improve understanding. Do not remove necessary
technical detail to meet an arbitrary word count. Preserve exact identifiers,
error text, and required legal wording.

## Make the result pleasant to use

Use descriptive headings and links. Use tables for comparisons and numbered
lists for sequences. Keep heading levels in order. Put code in fenced blocks
with a language when known. Explain diagrams in text and supply useful image
descriptions; color alone must not carry meaning. Keep examples small and use
fictional, non-sensitive data.

The first screen should explain the page's purpose. Remove chat transcripts,
generated filler, repeated policy, empty headings, and stale promises. A new
reader should not need the author's conversation history.

## Review documentation as a deliverable

For every affected document, verify technical facts against the implemented
contract and its supported version. Follow changed procedures in a suitable
fixture. Check links, navigation, commands, and the rendered result. Record
actual checks and limitations in the work item or review, as described in
[verification](verification.md).

Automated checks can detect broken links and missing fields. They cannot prove
that instructions are safe, complete, comprehensible, or formally STE-compliant.
Review those properties directly. Update documentation with the behavior it
describes; use the [workflow](workflow.md) to track any separate deliverable.
