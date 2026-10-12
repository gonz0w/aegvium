# Local review and PR policy

Private [gonz0w/aegvium](https://github.com/gonz0w/aegvium) follows NAS's local-evidence
approach. Actions are disabled. Checks run in the foreground with `make verify`;
there is no hosted fallback, self-hosted runner or success-status publisher.
FWS/EdgeWall runner workflows are not copied into Aegvium. GitHub does not enforce
local test results; Cam must inspect the evidence before merging.

Before publishing a change, inspect the complete diff, verify signed contributor
commits and author DCO trailers, and run checks from a clean identified candidate.
Attach source/tree/base, actual PR title, commands/results and relevant native
evidence to the PR. Local hooks are bypassable; they do not enforce remote review.
`tools/check-dco.py BASE_SHA HEAD_SHA` checks matching author trailers. Use
`git verify-commit` for each contributor commit and `git verify-tag` for release
tags against configured trusted signing keys. Do not describe DCO as signature
verification. No automated source-bound review harness or NAS test-selection/reuse
mechanism is adopted yet. Record identities and fresh results explicitly.

## PR procedure

Fetch `origin`, start a short-lived `codex/` branch from current `origin/main`,
and commit the scoped change with `git commit -S -s`. Before pushing, use a clean checkout:

```sh
git fetch origin
git status --porcelain
base_sha=$(git rev-parse origin/main)
candidate_sha=$(git rev-parse HEAD)
git merge-base --is-ancestor "$base_sha" "$candidate_sha"
git rev-list "$base_sha..$candidate_sha" |
while IFS= read -r contributor_sha; do
    git -c gpg.ssh.allowedSignersFile=.tools/allowed_signers verify-commit "$contributor_sha" || exit 1
done
.tools/venv/bin/python3 tools/check-dco.py "$base_sha" "$candidate_sha"
make verify
test "$candidate_sha" = "$(git rev-parse HEAD)"
test -z "$(git status --porcelain)"
```

Stop if any command fails or initial status is nonempty. The trusted public signer
file is deliberately configured per clone; do not download and trust arbitrary keys.
Record resolved head/tree/base IDs, actual Conventional Commit PR title, commands,
results and relevant native evidence in the PR. Private logs remain ignored;
inspect and sanitize anything shared. A changed candidate/base/title needs updated
evidence. Push the topic branch and use `gh pr create --base main --body-file` with
the reviewed description. Leave every PR open for Cam; do not merge automatically.

## Remote enforcement

The active main ruleset requires PRs, signed commits, linear history and resolved
conversations, and blocks deletion/force pushes. The solo maintainer phase uses
zero mandatory independent approvals and no mandatory CODEOWNERS approval; the
owner cannot approve their own PR. There are no bypass actors or required status
checks. Add independent approval when a distinct reviewer joins. Only squash
merges are enabled, auto-merge is disabled, and merged branches are deleted.
Preserve DCO trailers in the canonical signed squash commit. Release `v*` tags
cannot be updated/deleted and must separately pass signature/release review.

Versioned [main](../../.github/main-ruleset.json) and
[release-tag](../../.github/release-tags-ruleset.json) definitions do not apply
themselves. The [bootstrap record](github.md) identifies settings observed remotely.
The initial signed foundation seeded main before protections; all subsequent
changes require PRs. An uncommitted test run validates working files only.

Product changes add go vet/test, focused staticcheck and govulncheck, bounded
parser/security fuzzing and race checks where supported. Native security, recovery,
performance and accessibility gates remain separate. A skipped capability cannot
be counted as passing. Keep fixture credentials and unsanitized logs ignored.
