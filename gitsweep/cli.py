from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .report import write
from .scan import scan

COLOR = {"critical": "\033[31m", "high": "\033[33m", "medium": "\033[93m",
         "low": "\033[36m", "ok": "\033[32m", "off": "\033[0m", "dim": "\033[2m"}


def _c(s: str, key: str, enabled: bool) -> str:
    return f"{COLOR[key]}{s}{COLOR['off']}" if enabled else s


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="gitsweep",
        description="Audit a directory of git repos for committed secrets, "
                    "build junk, and work that isn't backed up.",
    )
    ap.add_argument("root", nargs="?", default=".", help="directory to scan")
    ap.add_argument("--depth", type=int, default=2,
                    help="how deep to look for repos (default: 2)")
    ap.add_argument("--html", metavar="FILE", help="write an HTML report")
    ap.add_argument("--min-severity", choices=["critical", "high", "medium", "low"],
                    default="low", help="hide findings below this level")
    ap.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "never"],
                    default="never", help="exit non-zero if anything at or above this "
                                          "level is found (for CI)")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--version", action="version", version=f"gitsweep {__version__}")
    args = ap.parse_args(argv)

    root = Path(args.root).expanduser().resolve()
    if not root.exists():
        print(f"gitsweep: no such directory: {root}", file=sys.stderr)
        return 2

    color = sys.stdout.isatty() and not args.no_color
    order = ["critical", "high", "medium", "low"]
    cutoff = order.index(args.min_severity)

    repos = scan(root, args.depth)
    if not repos:
        print(f"No git repositories found under {root}")
        return 0

    shown = flagged = 0
    for r in repos:
        fs = [f for f in r.findings if order.index(f.severity) <= cutoff]
        if not fs:
            continue
        flagged += 1
        worst = fs[0].severity
        print(f"\n{_c('●', worst, color)} {r.name}  "
              f"{_c(f'({len(fs)} finding{"s" if len(fs) != 1 else ""}, score {r.score})', 'dim', color)}")
        for f in fs:
            shown += 1
            print(f"    {_c(f.severity.upper().ljust(8), f.severity, color)} {f.title}")
            if f.paths:
                for p in f.paths[:3]:
                    print(f"             {_c(p, 'dim', color)}")
                if len(f.paths) > 3:
                    print(f"             {_c(f'… and more', 'dim', color)}")

    clean = len(repos) - flagged
    print(f"\n{len(repos)} repos scanned · {shown} findings · "
          f"{_c(f'{clean} clean', 'ok', color)}")

    if args.html:
        dest = write(repos, str(root), Path(args.html).expanduser())
        print(f"HTML report: {dest}")

    if args.fail_on != "never":
        limit = order.index(args.fail_on)
        if any(order.index(f.severity) <= limit for r in repos for f in r.findings):
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
