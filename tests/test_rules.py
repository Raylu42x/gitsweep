"""Rule tests. Each builds a real git repo in a temp dir — no mocking."""

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from gitsweep.scan import inspect, discover, is_repo


def git(d, *a):
    subprocess.run(["git", "-C", str(d), *a], capture_output=True, check=False)


def make_repo(tmp: Path, files: dict[str, str], commit=True) -> Path:
    tmp.mkdir(parents=True, exist_ok=True)
    git(tmp, "init", "-q", "-b", "main")
    git(tmp, "config", "user.email", "t@t.t")
    git(tmp, "config", "user.name", "t")
    for rel, content in files.items():
        p = tmp / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    if commit:
        git(tmp, "add", "-A")
        git(tmp, "commit", "-qm", "init")
    return tmp


def rules_fired(repo):
    return {f.rule for f in repo.findings}


class TestRules(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_tracked_database_is_critical(self):
        r = inspect(make_repo(self.tmp / "a", {
            "README.md": "x", ".gitignore": "", "data/app.db": "sqlite",
        }))
        self.assertIn("tracked-database", rules_fired(r))
        f = next(f for f in r.findings if f.rule == "tracked-database")
        self.assertEqual(f.severity, "critical")
        self.assertIn("data/app.db", f.paths)

    def test_db_sidecars_detected(self):
        r = inspect(make_repo(self.tmp / "b", {
            "README.md": "x", ".gitignore": "",
            "d.db-wal": "w", "d.db-shm": "s", "x.sqlite3": "q",
        }))
        f = next(f for f in r.findings if f.rule == "tracked-database")
        self.assertEqual(len(f.paths), 3)

    def test_env_example_is_not_flagged(self):
        r = inspect(make_repo(self.tmp / "c", {
            "README.md": "x", ".gitignore": "", ".env.example": "KEY=",
        }))
        self.assertNotIn("tracked-env", rules_fired(r))

    def test_real_env_is_flagged(self):
        r = inspect(make_repo(self.tmp / "d", {
            "README.md": "x", ".gitignore": "", ".env": "SECRET=hunter2",
        }))
        self.assertIn("tracked-env", rules_fired(r))

    def test_private_key_flagged(self):
        r = inspect(make_repo(self.tmp / "e", {
            "README.md": "x", ".gitignore": "", "certs/server.pem": "-----BEGIN",
        }))
        self.assertIn("tracked-private-key", rules_fired(r))

    def test_missing_readme_and_gitignore(self):
        r = inspect(make_repo(self.tmp / "f", {"main.py": "print()"}))
        fired = rules_fired(r)
        self.assertIn("missing-readme", fired)
        self.assertIn("missing-gitignore", fired)

    def test_clean_repo_has_no_findings(self):
        r = inspect(make_repo(self.tmp / "g", {
            "README.md": "# hi", ".gitignore": "*.pyc", "main.py": "print()",
        }))
        # no remote is expected for a temp repo; ignore that one
        self.assertEqual(rules_fired(r) - {"no-remote"}, set())

    def test_untracked_files_are_flagged(self):
        p = make_repo(self.tmp / "h", {"README.md": "x", ".gitignore": ""})
        (p / "scratch.txt").write_text("unsaved work")
        r = inspect(p)
        self.assertIn("uncommitted-work", rules_fired(r))

    def test_junk_severity_scales_with_size(self):
        small = inspect(make_repo(self.tmp / "i", {
            "README.md": "x", ".gitignore": "", "__pycache__/m.pyc": "z",
        }))
        f = next(f for f in small.findings if f.rule == "tracked-junk")
        self.assertEqual(f.severity, "medium")

        big = inspect(make_repo(self.tmp / "j", {
            "README.md": "x", ".gitignore": "",
            "__pycache__/big.pyc": "z" * (6 * 1024 * 1024),
        }))
        f = next(f for f in big.findings if f.rule == "tracked-junk")
        self.assertEqual(f.severity, "high")

    def test_empty_repo(self):
        r = inspect(make_repo(self.tmp / "k", {}, commit=False))
        self.assertIn("empty-repo", rules_fired(r))

    def test_score_drops_with_severity(self):
        clean = inspect(make_repo(self.tmp / "l", {
            "README.md": "x", ".gitignore": "", "a.py": "1",
        }))
        bad = inspect(make_repo(self.tmp / "m", {
            "README.md": "x", ".gitignore": "", "app.db": "sqlite",
        }))
        self.assertGreater(clean.score, bad.score)
        self.assertLessEqual(bad.score, 60)


class TestDiscovery(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_finds_nested_repos_but_not_inside_them(self):
        make_repo(self.tmp / "one", {"README.md": "x"})
        make_repo(self.tmp / "group" / "two", {"README.md": "x"})
        # a repo nested inside another must not be double-reported
        make_repo(self.tmp / "one" / "inner", {"README.md": "x"})
        found = {p.name for p in discover(self.tmp, depth=3)}
        self.assertEqual(found, {"one", "two"})

    def test_worktree_git_file_is_recognised(self):
        """Linked worktrees use a .git FILE, not a directory."""
        d = self.tmp / "wt"
        d.mkdir()
        (d / ".git").write_text("gitdir: /somewhere/else")
        self.assertTrue(is_repo(d))


if __name__ == "__main__":
    unittest.main(verbosity=2)
