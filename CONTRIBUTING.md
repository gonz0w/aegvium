# Contributing

Read [agent instructions](AGENTS.md) and the active scoped PRD, EDD and Test Design. Follow [local review](docs/engineering/review.md).

Use focused `codex/` branches from current origin/main. Conventional Commit subjects and PR titles are required. Sign commits and release tags; include the author's DCO sign-off with `git commit -S -s`. Signing and DCO are separate requirements; never downgrade either silently. Contributions use BSD-3-Clause and retain upstream notices.

Run `make tools hooks` and `make verify`. No GitHub Actions, runners or remote success publisher. Meaningful runtime changes require abuse/failure/recovery tests and disposable OpenBSD evidence. Leave PRs open for maintainer review. No live deployment or release is implied by development authorization.

Use the [GitHub workflow](docs/engineering/github-workflow.md) and [private Project](https://github.com/users/gonz0w/projects/5) for live work. Main is seeded; subsequent changes require PRs.
