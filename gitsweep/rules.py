"""Detection rules.

Each rule is a function that takes a Repo and yields Findings. Rules are
deliberately independent and cheap — the whole point is that you can run this
across a hundred repos without thinking about it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterator


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


@dataclass
class Finding:
    rule: str
    severity: str
    title: str
    detail: str
    paths: list[str] = field(default_factory=list)
    fix: str = ""

    @property
    def rank(self) -> int:
        return SEVERITY_ORDER.get(self.severity, 9)


# --- helpers ----------------------------------------------------------------

def _bytes_human(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}GB"


def _sample(paths: list[str], n: int = 6) -> list[str]:
    return paths[:n]


# --- rules ------------------------------------------------------------------

DB_SUFFIXES = (".db", ".sqlite", ".sqlite3", ".db-wal", ".db-shm", ".mdb")
DB_RE = re.compile(r"\.(db|sqlite3?|mdb)(-wal|-shm)?$", re.I)


def tracked_database(repo) -> Iterator[Finding]:
    """A live database in git leaks whatever is inside it and conflicts on merge."""
    hits = [p for p in repo.tracked if DB_RE.search(p)]
    if not hits:
        return
    yield Finding(
        rule="tracked-database",
        severity="critical",
        title="Live database committed to git",
        detail=(
            f"{len(hits)} database file(s) are tracked. Databases routinely hold "
            "password hashes, session tokens, API keys and personal data — all of "
            "which stay readable in git history even after the file is deleted. "
            "They also conflict on every merge and grow history on every write."
        ),
        paths=_sample(hits),
        fix="git rm --cached <file> && add it to .gitignore, then rotate any "
            "credentials the database contained. Removing it from HEAD does not "
            "remove it from history — use git filter-repo if the repo is shared.",
    )


ENV_RE = re.compile(r"(^|/)\.env(\.|$)(?!example|sample|template)", re.I)


def tracked_env(repo) -> Iterator[Finding]:
    hits = [p for p in repo.tracked
            if ENV_RE.search(p) and not re.search(r"\.(example|sample|template)$", p, re.I)]
    if not hits:
        return
    yield Finding(
        rule="tracked-env",
        severity="critical",
        title="Environment file committed",
        detail="A .env file is tracked. These exist specifically to hold secrets.",
        paths=_sample(hits),
        fix="git rm --cached the file, gitignore it, and rotate every credential "
            "it contained.",
    )


KEY_RE = re.compile(r"\.(pem|key|p12|pfx|keystore|jks)$|(^|/)id_(rsa|dsa|ecdsa|ed25519)$", re.I)


def tracked_private_key(repo) -> Iterator[Finding]:
    hits = [p for p in repo.tracked if KEY_RE.search(p)]
    if not hits:
        return
    yield Finding(
        rule="tracked-private-key",
        severity="critical",
        title="Private key or certificate committed",
        detail="Key material is tracked in git.",
        paths=_sample(hits),
        fix="Remove from the index, gitignore, and regenerate the key. Assume it "
            "is compromised.",
    )


DEBUG_DIRS = (
    ".playwright-mcp/", "playwright-report/", "test-results/", ".pytest_cache/",
    "__pycache__/", ".mypy_cache/", ".ruff_cache/", "node_modules/",
    ".next/", ".nuxt/", "DerivedData/", ".gradle/", ".terraform/",
)


def tracked_junk(repo) -> Iterator[Finding]:
    hits = [p for p in repo.tracked if any(d in p for d in DEBUG_DIRS)]
    if not hits:
        return
    total = sum(repo.size_of(p) for p in hits)
    yield Finding(
        rule="tracked-junk",
        severity="medium" if total < 5 * 1024 * 1024 else "high",
        title="Build output or debug artifacts committed",
        detail=(
            f"{len(hits)} generated file(s), {_bytes_human(total)}. These are "
            "regenerated on every run and only add noise to diffs and weight to "
            "clones."
        ),
        paths=_sample(hits),
        fix="git rm -r --cached the directory and add it to .gitignore.",
    )


USER_STATE = ("xcuserdata/", ".idea/", ".vscode/settings.json", ".DS_Store", "Thumbs.db")


def tracked_user_state(repo) -> Iterator[Finding]:
    hits = [p for p in repo.tracked if any(u in p for u in USER_STATE)]
    if not hits:
        return
    yield Finding(
        rule="tracked-user-state",
        severity="low",
        title="Per-user editor or OS state committed",
        detail=f"{len(hits)} file(s) that belong to one person's machine, not the project.",
        paths=_sample(hits),
        fix="git rm --cached and gitignore.",
    )


def missing_gitignore(repo) -> Iterator[Finding]:
    if ".gitignore" in repo.tracked or not repo.tracked:
        return
    yield Finding(
        rule="missing-gitignore",
        severity="medium",
        title="No .gitignore",
        detail="Without one, build output and local state get committed by accident — "
               "which is how most of the other findings in this report happen.",
        fix="Add a .gitignore appropriate to the stack.",
    )


def missing_readme(repo) -> Iterator[Finding]:
    if not repo.tracked:
        return
    if any(p.lower().startswith("readme") and "/" not in p for p in repo.tracked):
        return
    yield Finding(
        rule="missing-readme",
        severity="medium",
        title="No README",
        detail="Nothing explains what this repo is, how to run it, or whether it works.",
        fix="Add a README covering what it is, how to build, and current status.",
    )


def missing_license(repo) -> Iterator[Finding]:
    if not repo.tracked or repo.private is not False:
        return
    if any(p.lower().startswith(("license", "licence", "copying")) and "/" not in p
           for p in repo.tracked):
        return
    yield Finding(
        rule="missing-license",
        severity="low",
        title="Public repo with no LICENSE",
        detail="Without a licence, default copyright applies and nobody may legally "
               "use, copy, or contribute to the code.",
        fix="Add a LICENSE file. MIT unless there's a reason otherwise.",
    )


def uncommitted_work(repo) -> Iterator[Finding]:
    if not repo.dirty:
        return
    n = len(repo.dirty)
    untracked = [p for p, s in repo.dirty if s == "??"]
    sev = "high" if len(untracked) > 3 else "medium"
    yield Finding(
        rule="uncommitted-work",
        severity=sev,
        title=f"{n} uncommitted change(s)",
        detail=(
            f"{len(untracked)} untracked, {n - len(untracked)} modified. Untracked "
            "files exist on exactly one disk — they are not backed up by anything."
        ),
        paths=_sample([p for p, _ in repo.dirty]),
        fix="Commit it, or add it to .gitignore if it's genuinely disposable.",
    )


def unpushed_commits(repo) -> Iterator[Finding]:
    if repo.ahead <= 0:
        return
    yield Finding(
        rule="unpushed-commits",
        severity="medium",
        title=f"{repo.ahead} commit(s) not pushed",
        detail="Committed locally but not on any remote — one disk failure from gone.",
        fix="git push",
    )


def no_remote(repo) -> Iterator[Finding]:
    if repo.remote or not repo.tracked:
        return
    yield Finding(
        rule="no-remote",
        severity="high",
        title="No remote configured",
        detail="This repo exists only on this machine. Git is version control, not "
               "a backup, until there is somewhere else to push to.",
        fix="Add a remote and push.",
    )


def empty_repo(repo) -> Iterator[Finding]:
    if repo.commits != 0:
        return
    yield Finding(
        rule="empty-repo",
        severity="low",
        title="Repository has no commits",
        detail="Initialised but nothing committed.",
        fix="Commit the initial state, or remove the directory.",
    )


ALL_RULES = [
    tracked_database, tracked_env, tracked_private_key,
    tracked_junk, tracked_user_state,
    missing_gitignore, missing_readme, missing_license,
    uncommitted_work, unpushed_commits, no_remote, empty_repo,
]
