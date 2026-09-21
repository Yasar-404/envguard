from __future__ import annotations

import argparse
import dataclasses
import sys
import textwrap
from collections.abc import Sequence
from pathlib import Path

from envguard import __version__
from envguard.baseline import load_baseline, write_baseline
from envguard.config import Config, find_config, load_config
from envguard.models import EnvGuardError, Severity
from envguard.reporting import render_json, render_text
from envguard.rules import RULES
from envguard.scanner import scan

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

_EPILOG = """\
exit codes:
  0  no findings
  1  findings detected
  2  usage, configuration or runtime error
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="envguard",
        description="Scan source code and Git history for exposed secrets.",
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"envguard {__version__}")
    commands = parser.add_subparsers(dest="command", metavar="<command>")

    scan_cmd = commands.add_parser(
        "scan",
        help="scan a directory or file for secrets",
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    scan_cmd.add_argument("path", nargs="?", default=".", help="directory or file (default: .)")
    scan_cmd.add_argument("--json", action="store_true", help="print a JSON report")
    scan_cmd.add_argument(
        "--severity",
        choices=[s.label for s in Severity],
        help="only report findings at or above this severity",
    )
    scan_cmd.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="PATTERN",
        help="gitignore-style pattern to skip (repeatable)",
    )
    scan_cmd.add_argument("--config", type=Path, help="path to a config file")
    scan_cmd.add_argument(
        "--history", action="store_true", help="also scan lines added in Git history"
    )
    scan_cmd.add_argument(
        "--max-commits", type=int, metavar="N", help="with --history, inspect at most N commits"
    )
    scan_cmd.add_argument(
        "--baseline", type=Path, metavar="FILE", help="ignore findings recorded in this baseline"
    )
    scan_cmd.add_argument(
        "--write-baseline",
        type=Path,
        metavar="FILE",
        help="record all current findings in FILE and exit 0",
    )
    scan_cmd.set_defaults(handler=_scan)

    rules_cmd = commands.add_parser("rules", help="list the detection rules")
    rules_cmd.set_defaults(handler=_list_rules)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help(sys.stderr)
        return EXIT_ERROR
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")
    try:
        return int(args.handler(args))
    except EnvGuardError as exc:
        print(f"envguard: error: {exc}", file=sys.stderr)
    except KeyboardInterrupt:
        print("envguard: interrupted", file=sys.stderr)
    return EXIT_ERROR


def _scan(args: argparse.Namespace) -> int:
    if args.max_commits is not None and args.max_commits < 1:
        raise EnvGuardError("--max-commits must be at least 1")
    if args.max_commits is not None and not args.history:
        raise EnvGuardError("--max-commits only applies together with --history")

    root = Path(args.path).resolve()
    config = _load(args.config, root)
    if args.severity:
        config = dataclasses.replace(config, min_severity=Severity.parse(args.severity))
    if args.exclude:
        config = dataclasses.replace(config, exclude=(*config.exclude, *args.exclude))

    if args.baseline and args.write_baseline:
        raise EnvGuardError("--baseline and --write-baseline cannot be used together")

    if args.write_baseline:
        result = scan(root, config, history=args.history, max_commits=args.max_commits)
        count = write_baseline(args.write_baseline, result.findings)
        print(f"Wrote {count} finding(s) to {args.write_baseline}", file=sys.stderr)
        return EXIT_CLEAN

    baseline_path = args.baseline or config.baseline
    baseline = load_baseline(baseline_path) if baseline_path else frozenset()
    result = scan(
        root, config, history=args.history, max_commits=args.max_commits, baseline=baseline
    )
    report = render_json if args.json else render_text
    print(report(result, args.path))
    return EXIT_FINDINGS if result.findings else EXIT_CLEAN


def _load(explicit: Path | None, root: Path) -> Config:
    if explicit is not None:
        return load_config(explicit)
    found = find_config(root if root.is_dir() else root.parent)
    return load_config(found) if found else Config()


def _list_rules(_: argparse.Namespace) -> int:
    for rule in RULES:
        print(f"{rule.id:<22}{rule.severity.label:<8}{rule.name}")
        print(textwrap.indent(textwrap.fill(rule.description, width=72), " " * 30))
    return EXIT_CLEAN
