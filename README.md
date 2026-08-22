# gitsweep

Audit a whole directory of git repositories for things that shouldn't be in
them: committed databases, leaked keys, build output, and work that exists on
exactly one disk.

Stdlib only. No install, no config, no network.

```bash
python3 -m gitsweep.cli ~/Repos --html audit.html
```

```
● Chore App  (1 finding, score 44)
    CRITICAL Live database committed to git
             data/chore-app.db
             data/chore-app.db-shm
             data/chore-app.db-wal

● formhack  (1 finding, score 60)
    CRITICAL Live database committed to git
             n8n/database.sqlite

78 repos scanned · 10 findings · 69 clean
```

## Why this exists

Secret scanners like gitleaks and trufflehog look for *string patterns* — an
AWS key, a JWT, a high-entropy blob. They are good at that and gitsweep does not
try to compete.

But the worst things in a repo are usually not strings. They're **files that
should never have been added at all**: a live SQLite database holding session
tokens and password hashes, an Android signing keystore, a `.env`, 116 debug
screenshots, `node_modules`. A pattern scanner walks straight past a binary
`.db` file. And none of those tools tell you the other thing that actually loses
work — that a repo has 29 untracked files and no remote.

gitsweep answers one question across many repos at once: *what's in here that
shouldn't be, and what isn't backed up?*

## What it checks

| Rule | Severity | Why it matters |
|---|---|---|
| `tracked-database` | critical | `.db`/`.sqlite` files hold password hashes, session tokens and personal data — and stay readable in history forever |
| `tracked-env` | critical | `.env` exists to hold secrets (`.env.example` is correctly ignored) |
| `tracked-private-key` | critical | `.pem`, `.key`, `.keystore`, `id_rsa` — assume compromised once committed |
| `tracked-junk` | medium/high | `node_modules`, `__pycache__`, `.next`, test artifacts. Severity scales with size |
| `tracked-user-state` | low | `xcuserdata`, `.idea`, `.DS_Store` — one person's machine, not the project |
| `no-remote` | high | Git isn't a backup until there's somewhere to push |
| `uncommitted-work` | medium/high | Untracked files exist on one disk only |
| `unpushed-commits` | medium | Committed, but still only local |
| `missing-gitignore` | medium | The root cause of most of the above |
| `missing-readme` | medium | Nothing says what it is or whether it works |
| `missing-license` | low | Public repos only — without one, nobody may legally use it |
| `empty-repo` | low | Initialised, never committed |

Each repo gets a score out of 100 (critical −40, high −20, medium −8, low −3).

## Usage

```
gitsweep [root] [--depth N] [--html FILE] [--min-severity LEVEL] [--fail-on LEVEL]
```

| Flag | Effect |
|---|---|
| `--depth N` | How far to look for repos. Default 2 |
| `--html FILE` | Write a self-contained HTML report |
| `--min-severity` | Hide findings below this level |
| `--fail-on` | Exit non-zero at or above this level — for CI |
| `--no-color` | Plain output |

Repos nested inside other repos aren't double-reported, and linked **worktrees
are detected properly** — they use a `.git` *file* rather than a directory,
which is an easy thing to get wrong.

### In CI

```bash
gitsweep . --depth 1 --fail-on critical
```

## HTML report

`--html` writes one self-contained file — no external CSS, fonts, or scripts.
It follows the viewer's light/dark preference, collapses clean repos, and
auto-expands anything critical or high.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

13 tests. Each builds a real git repository in a temp directory and runs the
real scanner against it — no mocks, no fixtures checked in.

## Limitations

- **Findings are heuristics, not proof.** A `.db` file might be an intentional
  test fixture. Read before acting.
- It inspects the **working tree and index**, not full history. A file removed
  from HEAD but still in history won't be flagged — and is still exposed.
- No entropy or pattern scanning. Use gitleaks alongside it, not instead of it.

## License

MIT
