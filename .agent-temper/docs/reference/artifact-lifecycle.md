# Artifact lifecycle

Keep the evidence and recovery assets the project needs, without retaining every
intermediate file. This reference supports the [workflow](workflow.md) and
[verification record](verification.md#record-enough-evidence). It grants no cleanup,
execution, sharing or storage authority. Existing holds and stronger retention,
security and recovery requirements take precedence.

## Decide before creating substantial output

Use the project's existing policy and work record. Before a build, test campaign,
experiment or download can create substantial output, identify its output location,
expected storage demand, owner and retention decision. Check available capacity
and reserve enough for active work and recovery. If the estimate exceeds the
project's budget, stop dependent generation and propose a smaller authorized run.
Do not launch another build or test merely to classify old output.

Record these durable choices inline in project policy or in a linked local rule:

- Locations for maintained source, retained evidence, rebuildable intermediates,
  reusable downloads and caches. Keep evidence separate from disposable output.
- A storage budget and finite size, count, age or event limits appropriate to each
  generated class. State the cleanup or review trigger and responsible owner.
- Evidence, release, incident and recovery holds, including what releases a hold.
  Record justified exceptions with an owner and review condition.
- Permitted cleanup actions, recovery method, required checks and any approval
  boundary. A retention limit identifies a candidate, not permission to delete it.

A small project can use a few lines. No mandatory directory names, retention
period, daemon, manifest service or new tracker is required. Record current
candidates and dispositions in the existing work item, not a parallel backlog.
If a required decision is missing, pause only work that depends on it.

## Retain by purpose

| Class | Default treatment, subject to local policy |
| --- | --- |
| Maintained source and unique data | Preserve tracked and uncommitted work, local-only commits, fixtures and irreplaceable inputs. Untracked or ignored does not mean disposable. |
| Acceptance and failure evidence | Keep the compact command/result record, source/input identity, relevant diagnostics and reproduction material for the required review, support and recovery period. Preserve failed, cancelled and inconclusive outcomes; never keep only the latest success. |
| Rebuildable intermediates | Use an owned temporary/output location. After the run and required evidence capture, remove only what the current authority permits. Retain the rebuild recipe and necessary input identities; do not call a file reproducible when its inputs or tools are unavailable. |
| Immutable downloads and installation media | Prefer one verified canonical copy per required content identity in an authorized location. Record origin, version and digest. Reuse compatible inputs instead of copying them into every dated run. |
| Compiler and dependency caches | Inspect their contents before eviction, then use supported controls with a finite budget. Share only where toolchain, target, trust and concurrency rules permit; isolate incompatible or untrusted inputs. A cache must not be the sole retained copy of source or evidence. |
| VM images, snapshots and overlays | Treat the complete backing chain as a dependency set. Retain every base referenced by a surviving image and every image needed for active work, debugging, release or recovery. A dated directory or an inactive VM is not evidence of independence. |
| Worktrees and version-control storage | Preserve dirty work, local-only history, active owners and recovery data. Use supported inspection and maintenance commands; never delete object packs, indexes or administrative directories by hand. |

A cache directory can contain more than rebuildable cache entries. Preserve fuzz
corpora, regression seeds, crash reproducers and retained executables or other
products even when nested under a cache root. Inspect the candidate tree and
classify those contents by purpose, ownership and retention need before eviction;
being generated does not prove they can be reproduced. Keep them until their own
retention conditions and authorized disposition are established. A supported
cache-cleaning command is not safe merely because the tool provides it. If it
cannot exclude protected contents, hold the affected eviction until an authorized
preservation plan protects the bytes and verifies their references. Do not move,
delete or rerun a retained product just to classify it.

Before removing a duplicate, verify content identity, references and the retained
copy's usability. Matching names or sizes do not prove equality. For large files,
use trusted existing digests where applicable or bound the verification effort.
A symlink, hard link or copy-on-write clone can have different modification and
recovery semantics; do not substitute one silently. Do not introduce shared
storage or change permissions merely to save space.

Retain the current accepted evidence and the distinct failures or baseline inputs
still needed for unresolved work. Older copies can become candidates when local
retention conditions are satisfied and their unique evidence is preserved.
A compact summary does not replace raw material needed to investigate, reproduce,
review or recover. Avoid duplicate source archives when retained version-control
revisions already preserve the required bytes. An unpushed or expiring revision
is not a durable substitute without a verified retention plan.

## Inspect before cleanup

1. Confirm the bounded work item, authority, affected repositories, current owners
   and explicit holds. Inspect current worktree state and relevant processes or
   locks without stopping them. Unknown ownership or use blocks that candidate.
2. Inventory the selected locations read-only. Separate apparent file size from
   allocated space, and account for sparse images, shared blocks and hard links.
   Record the measurement method and uncertainty; sizes are not guaranteed savings.
3. For each candidate group, record location, purpose, estimated bytes, evidence
   to retain, references/dependencies, reproduction or recovery route and proposed
   disposition. Keep personal paths, private logs and sensitive data out of public
   records. Use a permitted private record when exact paths are needed.
4. Verify that retained evidence and artifacts remain resolvable. For disk images,
   inspect backing-chain metadata with supported tools before changing any member.
   Trace references from surviving runs, configurations and manifests. If the
   dependency set cannot be established, preserve it and report the blocker.
5. Preview the exact bounded selection with the supported dry-run or an explicit
   candidate list. Exclude active paths, holds and unrelated work. Recheck state
   before execution; a prior inventory can become stale.

Elapsed age, duplicate-looking directory names, ignore rules, a successful build
or a clean working tree alone cannot authorize cleanup. Preserve unfinished work
and required evidence even when its budget is exceeded; escalate the storage
conflict rather than silently discarding it.

## Execute and reconcile within authority

Use the least destructive authorized action. Prefer a supported recoverable
removal or a verified retained copy when recovery is required. Moving files to
Trash or a quarantine on the same volume generally does not reclaim their space;
state that honestly and record the next decision. Permanent deletion and emptying
recovery stores retain their existing confirmation requirements. Do not silently
schedule a later purge. Do not upload or archive data elsewhere without authority.

For worktrees, preview supported pruning only after confirming the target is
actually gone, not temporarily inaccessible, and no owner still uses it. For
Git storage, use supported diagnostics and maintenance under project authority.
Overlapping packs alone do not establish redundant removable files. Preserve
needed refs, reflogs, recovery history and concurrent operations; do not add
aggressive pruning, expiry changes or history rewriting to a routine cleanup.

After the authorized operation, check the affected references, retained evidence
and repository/worktree integrity using the permitted non-destructive checks.
Do not run native workloads or new expensive verification outside the selected
scope. Record actual before/after allocation and free space, completed actions,
recoverable items, remaining holds and unavailable checks. Do not report estimated
or quarantined bytes as reclaimed. Stop and report an unexpected effect before
continuing with other dependent candidates.

At a delivery or handoff, account for generated output: what remains, why it is
needed, where the canonical record is and what event permits its cleanup. Use the
existing work record. Finish owned temporary work within its authority instead of
leaving a new dated copy after every attempt. A maintenance schedule needs separate
authority; this guidance does not enable recurring deletion.

## Fictional example

A fictional project has one retained installer, an active VM overlay, a failed
run awaiting review and an older successful run. The overlay points to a base
inside the older run. The lead preserves that base and the failed run's relevant
diagnostics, even though both directories exceed the usual age limit. Identical
installer copies become cleanup candidates only after digest and reference
checks. A cache inspection also finds a fuzz corpus and a retained executable.
The lead holds broad eviction until those contents have a verified preservation
plan under the project's authority. Disposable cache entries can then use the
supported size limit, not an ad hoc cross-project merge. The work item records
the holds, permitted recoverable removals and measured result; it does not claim
that moving files to Trash freed space or that a fresh VM test ran.

## Enforce the local boundary

A policy alone does not prevent output growth. Where the project selects an
artifact-producing runner, wire capacity checks before allocation, owned-output
cleanup on every exit path, and compact accounting at handoff. Include outputs
outside the checkout and concurrent peak demand. Use a staged or changed-object
Git guard for large generated binaries, with reviewed exceptions for real assets.
The optional [storage guard](https://github.com/gonz0w/agent-temper/blob/main/docs/how-to/check-storage.md) supplies read-only
preflight and index checks; it performs no cleanup or automatic consumer rollout.
