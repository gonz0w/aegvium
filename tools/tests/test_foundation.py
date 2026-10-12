# SPDX-License-Identifier: BSD-3-Clause
"""Regression coverage for foundation gates, using disposable Git repositories."""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SOURCE = Path(__file__).resolve().parents[2]


class FoundationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="installer-foundation-")
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name) / "repo"
        shutil.copytree(SOURCE, self.repo, ignore=shutil.ignore_patterns(".git", ".tools", "__pycache__", "bin", "dist"))
        self.git("init", "-b", "main")
        # TemporaryDirectory cleanup must not race detached Git object writers.
        # Local settings also override developer/runner global auto thresholds.
        self.git("config", "maintenance.auto", "false")
        self.git("config", "gc.auto", "0")
        self.git("config", "user.name", "Test Author")
        self.git("config", "user.email", "author@example.invalid")
        self.git("config", "commit.gpgsign", "false")
        self.git("config", "core.hooksPath", "/dev/null")

    def command(self, *args):
        return subprocess.run(args, cwd=self.repo, capture_output=True, text=True,
                              env={**os.environ, "GIT_CONFIG_NOSYSTEM": "1"})

    def git(self, *args):
        result = self.command("git", *args)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result.stdout.strip()

    def check(self):
        return self.command(sys.executable, "tools/check-repo.py")

    def commit(self, message, signoff=False):
        self.git("add", ".")
        args = ["commit", "-m", message]
        if signoff:
            args.append("-s")
        self.git(*args)
        return self.git("rev-parse", "HEAD")

    def test_commits_do_not_launch_background_maintenance(self):
        # A developer/runner global configuration must not enable asynchronous
        # object writers in a disposable repository that is immediately removed.
        global_config = Path(self.temp.name) / "global.gitconfig"
        global_config.write_text("[maintenance]\n\tauto = true\n[gc]\n\tauto = 1\n")
        trace = Path(self.temp.name) / "git.trace"
        with mock.patch.dict(os.environ, {"GIT_CONFIG_GLOBAL": str(global_config),
                                          "GIT_TRACE": str(trace)}):
            self.commit("test: commit disposable fixture", signoff=True)
            self.assertNotIn("maintenance run --auto", trace.read_text())
            self.assertNotIn("gc --auto", trace.read_text())
            self.assertEqual(self.git("config", "--get", "maintenance.auto"), "false")
            self.assertEqual(self.git("config", "--get", "gc.auto"), "0")

    def test_committed_whitespace_is_rejected_without_staged_changes(self):
        (self.repo / "probe.py").write_text("value = 1   \n")
        self.commit("test: add whitespace probe")
        self.assertEqual(self.git("diff", "--cached", "--name-only"), "")
        result = self.check()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("probe.py: line 1: trailing whitespace", result.stderr)

    def test_go_source_is_text_and_not_yaml(self):
        probe = self.repo / "probe.go"
        probe.write_text("package probe\n\nfunc Value() int { return 1 }\n")
        self.assertEqual(self.check().returncode, 0)
        probe.write_text("package probe   \n")
        self.assertIn("probe.go: line 1: trailing whitespace", self.check().stderr)

    def test_license_is_required(self):
        (self.repo / "LICENSE").unlink()
        self.assertIn("LICENSE: required file", self.check().stderr)

    def test_missing_stability_gate_is_rejected(self):
        (self.repo / "docs/testing/native-gate.md").unlink()
        self.assertIn("docs/testing/native-gate.md: required file", self.check().stderr)

    def test_symlinked_source_is_rejected(self):
        (self.repo / "alias.md").symlink_to("README.md")
        self.assertIn("alias.md: symlinks require an explicit policy", self.check().stderr)

    def test_markdown_hard_breaks_are_allowed(self):
        (self.repo / "probe.md").write_text("Intentional hard break  \nNext line\n")
        self.git("add", ".")
        result = self.check()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_github_actions_workflow_is_rejected(self):
        path = self.repo / ".github/workflows/repository.yml"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("permissions:\n  contents: read\njobs:\n  probe:\n    steps:\n      - uses: actions/checkout@main\n")
        self.assertIn("GitHub Actions workflows are prohibited", self.check().stderr)

    def test_even_pinned_github_actions_workflow_is_rejected(self):
        path = self.repo / ".github/workflows/repository.yml"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("permissions:\n  contents: read\njobs:\n  probe:\n    steps:\n      - uses: actions/checkout@" + "a" * 40 + "\n")
        self.assertIn("GitHub Actions workflows are prohibited", self.check().stderr)

    def test_duplicate_yaml_security_keys_are_rejected(self):
        path = self.repo / ".github/workflows/repository.yml"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("permissions:\n  contents: read\njobs: {}\npermissions:\n  contents: write\n")
        self.assertIn("duplicate YAML key: permissions", self.check().stderr)

    def test_secret_filename_with_spaces_is_rejected(self):
        (self.repo / "key with spaces.key").write_text("not a real key\n")
        self.assertIn("key with spaces.key: private-key", self.check().stderr)

    def test_missing_local_link_is_rejected(self):
        (self.repo / "probe.md").write_text("[missing](missing-document.md)\n")
        self.assertIn("missing local link target", self.check().stderr)

    def test_dco_requires_author_trailer_on_every_commit(self):
        base = self.commit("chore: create fixture", signoff=True)
        (self.repo / "probe.md").write_text("Probe\n")
        head = self.commit("docs: add probe")
        result = self.command(sys.executable, "tools/check-dco.py", base, head)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Missing author DCO sign-off", result.stderr)
        self.git("commit", "--amend", "--no-edit", "-s")
        head = self.git("rev-parse", "HEAD")
        result = self.command(sys.executable, "tools/check-dco.py", base, head)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_commit_hook_rejects_missing_or_wrong_signoff(self):
        message = self.repo / "message"
        for body in ("docs: add probe\n", "docs: add probe\n\nSigned-off-by: Other <other@example.invalid>\n"):
            message.write_text(body)
            self.assertNotEqual(self.command("sh", ".githooks/commit-msg", str(message)).returncode, 0)
        message.write_text("docs: add probe\n\nSigned-off-by: Test Author <author@example.invalid>\n")
        self.assertEqual(self.command("sh", ".githooks/commit-msg", str(message)).returncode, 0)


if __name__ == "__main__":
    unittest.main()
