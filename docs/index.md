# gitsweep docs

Start with [../README.md](../README.md) for usage, rules and limitations.

## Layout

| File | Job |
|---|---|
| `gitsweep/cli.py` | Arguments, terminal output, exit codes |
| `gitsweep/scan.py` | Finds repos and collects their git state into a `Repo` |
| `gitsweep/rules.py` | The checks. Each takes a `Repo` and yields `Finding`s |
| `gitsweep/report.py` | The self-contained HTML report |
| `tests/test_rules.py` | Tests that build real temporary git repos |

## Adding a rule

1. Write a function in `rules.py` that takes `repo` and yields `Finding`s.
2. Add it to `ALL_RULES`.
3. Add a test in `tests/test_rules.py`.

A rule that raises is skipped, so a bad rule can't stop a scan, but it also fails silently. Make sure
your test proves the rule fires.

## Known limits

- **Fetch status:** gitsweep compares against local remote-tracking refs and never fetches. A deleted
  remote can look up to date.
- **Dead remotes:** there is no rule for them yet. Checking `git ls-remote` would catch them.
- **False positives:** a tracked `.keystore` is always critical, even for a standard SDK debug key.
- **History:** only the current tree is scanned.

## Running tests

```bash
python3 -m unittest discover -s tests -v
```
