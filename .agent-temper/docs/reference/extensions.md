# Profiles, local rules, and adoption feedback

Keep the [method](../../METHOD.md) small. A profile is a reusable set of written
rules for a tool or practice. A local extension records rules needed by one
project. Both work through ordinary documents, reviews, and checks; they require
no plugin runtime or configuration language.

## Decide where a difference belongs

During adoption, identify the actual problem before replacing an existing
practice. Compare its effect on correctness, clarity, delivery, and maintenance.
A different tool, filename, or stronger check is not evidence of poor design.

| Finding | Appropriate response |
| --- | --- |
| A shared requirement is wrong, ambiguous, or unnecessarily constrains valid projects | Propose a core correction with a concrete example and the affected contract. Keep the current pin until a reviewed update is adopted. |
| A useful practice applies to a recognizable class of projects | Propose an optional profile. State when its benefit justifies its cost; do not make it mandatory for unrelated projects. |
| A rule depends on this product, platform, risk, or tool setup | Keep a local rule and link its canonical contract from project policy. |
| A project cannot meet an adopted requirement | Record a scoped deviation with its reason, approving authority, alternative safeguard, and review or expiry condition. Do not claim full conformance for that scope. |
| Guidance is obsolete, contradictory, or duplicates another authority | Replace it deliberately with current policy or a pointer. Preserve consequential decisions and historical evidence. |

An integration defect in a local checker is not automatically a defect in the
method. For example, a checker may need to recognize the bundle's license and
checksum manifest as documentation. Fix the narrow classification with positive
and negative tests; do not exempt an entire directory from behavior checks.

## Select and compose explicitly

Project policy names the selected profiles and local extensions. A file being
present in the bundle does not activate it. For each selection, identify:

- Its path, purpose, applicability, and source identity. A bundled profile uses
  the bundle's recorded immutable revision. A local rule belongs to the consumer
  source revision that contains it. An external extension needs its own immutable source
  identity, content hashes, retained content, and compatible redistribution terms.
- Its requirements and defaults, including any explicit mappings to local names.
- Its prerequisites, dependencies, known conflicts, and compatibility limits.
- The checks or walkthrough that demonstrate correct use, and who may approve
  updates, exceptions, or removal.

Keep this information in project policy or a linked extension record. Do not
create a second registry or copy a rule that already has a canonical home. A
small rule can be one paragraph; it does not need its own document.

Core requirements remain binding. A selected profile may fill a delegated choice,
replace a default with a justified choice, or strengthen a requirement. It cannot
silently relax another applicable requirement. A declared compatibility condition
must be satisfied before the profile applies.

Apply compatible rules together. File order, a newer timestamp, and an agent's
preference do not establish precedence. If two applicable rules conflict, stop
only dependent work and ask the authorized decision maker. Record which rule is
replaced, the scope, reason, and authority. A departure from a requirement needs
the explicit deviation described above. Adopted decisions persist across sessions.

No profile or extension grants access, merge, release, deployment, or operational
authority. A copied check or command is not automatically authorized to run.
Follow the project's existing authority and verification requirements.

## Organize local policy by responsibility

A project may keep small rules inline or use selected modules: ordinary documents
that each own one coherent policy. Keep `PROJECT.md` as the entry point to the
purpose, decision owner, adopted sources, selected modules and local choices.
Read the selected modules before affected work. A directory of files does not
select them. Shared technical profiles can come from any suitable retained,
versioned source; the portable method requires no particular standards provider.

| Home | Owns |
| --- | --- |
| Pinned method | Portable engineering requirements and composition rules. |
| Selected profile or policy module | Rules for a tool, practice, technical boundary or project concern. |
| Project policy | Explicit selections, local choices and who may change them. |
| Owning work item | Current scope, evidence, authorized attempts and continuation. |

Give a maintained requirement a stable identifier where cross-references or
exceptions need one. State whether it is a requirement, default or delegated
choice. Keep its wording in one home; reference that identity instead of copying
it into agent instructions, contribution guides and check scripts. A source pin
belongs in its provenance record; validators should consume the maintained record
rather than embed another current pin or fixed role count.

Each selected module identifies applicability, canonical path/source identity,
owner, prerequisites, declared incompatibilities, verification and change authority.
Local module bytes are bound by the containing consumer revision. Retained external
modules need the source, hashes and rights described above. Avoid dynamic includes,
remote imports and elaborate inheritance. A compact selection table is sufficient.
An optional machine-readable selection record must be explicitly adopted and
linked; it does not select itself or become another copy of the policy prose.

When replacing a rule, name its identifier/source, replacement, affected scope,
reason and authorizing decision. A local choice can fill a delegated decision or
replace a default; relaxing a requirement needs its approved deviation. The newest
file, most specific path, or apparently strictest rule is not automatic precedence.
Compatible obligations apply together; an unresolved conflict stops dependent work.

Keep currently active exceptions easy to find. Retain superseded decisions and
expired exceptions as labeled history or links, without requiring readers to
interpret them as current permission. An exception's expiry removes its allowance;
it does not erase the original requirement or renew an attempt. A future date
alone cannot establish that an event-limited exception is still active.

## Select checks and execution separately

For an actual change, distinguish four decisions:

1. Identify changed contracts and the evidence needed to accept them.
2. Identify the permitted executor, tools, isolation and resource limits for each check.
3. Establish availability and authority before execution; resolve a missing required gate.
4. Integrate or deliver only under the project's separate review and action authority.

Classify semantic effects, not extensions alone. An instruction edit may change
permissions or required checks; a role file may change available tools. A project
can define a standing method-maintenance boundary for a known set of passive
source checks, but its owner must approve the exact allowed actions/executors,
exclusions and integration gates. Copying a template grants no host permission
and does not waive an existing BSD, Windows, release or other requirement.

| Change | Questions for the project's check map |
| --- | --- |
| Method/provenance maintenance | Which obligations actually change? Are passive inventory, source, license, link and review checks sufficient under approved policy? |
| Role/configuration change | Does it alter model access, tools, fallback or authority? What configuration and observable client behavior must be checked before relying on it? |
| Product or data change | Which behavior, compatibility, security, native, recovery or user checks establish the affected outcome? |
| Policy, checker or delivery change | Who approves the changed contract? Which positive, rejection and failure cases prove its implementation? |
| Unknown impact | Investigate or select the conservative required checks; do not infer a lighter category. |

The check map records trigger, inputs, working directory/command or manual
procedure, permitted executor, expected result, evidence, review and stop/recovery
conditions. Identify local versus hosted checks and integration versus release or
operation. A structural checker cannot establish policy meaning or actual authority.
Use the [verification](verification.md) and [workflow](workflow.md) references.

A delivery adapter maps these concepts to the chosen engine, build tools, forge
and pipeline. Required checks must produce truthful outcomes for the selected
scope. An unavailable required executor remains a block until resolved through
the authorized process; a prose decision does not change enforced protections.
Adopting a policy or copying a pipeline does not qualify it. Exercise positive,
negative, unavailable and recovery paths before relying on a new check selector
or delivery implementation. No specific OS, provider, engine or agent is required.

## Check the combined result

Review the selected rules as one policy. Verify their pinned sources and local
links, then walk a representative work item from selection through completion.
Check that an agent can identify acceptance, required verification, review, and
integration authority without choosing between competing instructions.

These examples illustrate composition; they do not prescribe a project stack:

| Situation | Expected result |
| --- | --- |
| A project selects [strict test-first work](../../profiles/strict-test-first.md) and already has stronger security tests | The test-first profile applies alongside those tests; it does not replace them. |
| A project uses `status:needs-triage` for the GitHub profile's backlog meaning | Record the equivalent label mapping. Existing issues do not need a rename merely to match the default spelling. |
| Two selected profiles prescribe incompatible completion gates | Stop affected integration and obtain an explicit policy decision; do not pick the easier gate. |
| The local workflow repeats general rules and adds a product-specific evidence requirement | Replace general duplicates with links; retain the evidence requirement at its canonical local path. |

## Feed useful findings back

Record the observation and its impact in the adoption work item. When proposing
an upstream change, create a bounded upstream issue with a sanitized example,
the simpler alternative, intended applicability, and a way to validate the result.
Link the consumer and upstream issues where publication is authorized. Never copy
private source or evidence into a public proposal.

Review an upstream change under the upstream repository's policy. Consumers then
adopt it through their normal update process; an upstream merge does not alter
their pins or settled choices. Recheck dependencies, conflicts, local mappings,
and representative work when updating or removing an extension. Remove obsolete
rules coherently without discarding evidence or leaving competing instructions.
