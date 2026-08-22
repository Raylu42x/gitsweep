"""Repo discovery and git introspection."""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from .rules import ALL_RULES, Finding


def _git(repo_dir: Path, *args: str, timeout: int = 30) -> str:
    try:
        out = subprocess.run(
            ["git", "-C", str(repo_dir), *args],
            capture_output=True, text=True, timeout=timeout,
        )
        return out.stdout if out.returncode == 0 else ""
    except (subprocess.TimeoutExpired, OSError):
        return ""


@dataclass
class Repo:
    path: Path
    name: str
    tracked: list[str] = field(default_factory=list)
    dirty: list[tuple[str, str]] = field(default_factory=list)
    remote: str = ""
    branch: str = ""
    ahead: int = 0
    commits: int = 0
    private: bool | None = None
    findings: list[Finding] = field(default_factory=list)
    _sizes: dict[str, int] = field(default_factory=dict, repr=False)

    def size_of(self, rel: str) -> int:
        if rel not in self._sizes:
            try:
                self._sizes[rel] = (self.path / rel).stat().st_size
            except OSError:
                self._sizes[rel] = 0
        return self._sizes[rel]

    @property
    def worst(self) -> int:
        return min((f.rank for f in self.findings), default=9)

    @property
    def score(self) -> int:
        """0-100. Starts at 100, loses points per finding by severity."""
        weights = {"critical": 40, "high": 20, "medium": 8, "low": 3}
        lost = sum(weights.get(f.severity, 0) for f in self.findings)
        return max(0, 100 - lost)


def is_repo(p: Path) -> bool:
    """True for a normal checkout or a linked worktree (.git may be a file)."""
    return (p / ".git").exists()


def discover(root: Path, depth: int = 2) -> list[Path]:
    """Find git repos under root, without descending into repos themselves."""
    found: list[Path] = []

    def walk(d: Path, level: int) -> None:
        if level > depth:
            return
        try:
            entries = sorted(x for x in d.iterdir() if x.is_dir())
        except OSError:
            return
        for e in entries:
            if e.name in {".git", "node_modules", "__pycache__", ".venv", "venv"}:
                continue
            if is_repo(e):
                found.append(e)
                continue          # don't recurse into a repo
            walk(e, level + 1)

    if is_repo(root):
        found.append(root)
    else:
        walk(root, 1)
    return found


def inspect(path: Path) -> Repo:
    repo = Repo(path=path, name=path.name)

    files = _git(path, "ls-files")
    repo.tracked = [l for l in files.splitlines() if l]

    status = _git(path, "status", "--porcelain")
    for line in status.splitlines():
        if len(line) > 3:
            repo.dirty.append((line[3:].strip(), line[:2].strip()))

    repo.remote = _git(path, "remote", "get-url", "origin").strip()
    repo.branch = _git(path, "rev-parse", "--abbrev-ref", "HEAD").strip()

    count = _git(path, "rev-list", "--count", "HEAD").strip()
    repo.commits = int(count) if count.isdigit() else 0

    if repo.remote and repo.branch:
        ahead = _git(path, "rev-list", "--count",
                     f"origin/{repo.branch}..HEAD").strip()
        repo.ahead = int(ahead) if ahead.isdigit() else 0

    for rule in ALL_RULES:
        try:
            repo.findings.extend(rule(repo))
        except Exception:
            continue          # a broken rule must never kill the scan

    repo.findings.sort(key=lambda f: f.rank)
    return repo


def scan(root: Path, depth: int = 2) -> list[Repo]:
    repos = [inspect(p) for p in discover(root, depth)]
    repos.sort(key=lambda r: (r.worst, -len(r.findings), r.name.lower()))
    return repos
