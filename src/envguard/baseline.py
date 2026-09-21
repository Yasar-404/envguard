"""Baseline files: accept the findings that exist today and report only new ones."""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path

from envguard.models import EnvGuardError, Finding

BASELINE_VERSION = "1"


class BaselineError(EnvGuardError):
    pass


def load_baseline(path: Path) -> frozenset[str]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise BaselineError(f"cannot read baseline {path}: {exc.strerror}") from exc
    except ValueError:
        raise BaselineError(f"baseline {path} is not valid JSON") from None

    if not isinstance(raw, dict) or raw.get("version") != BASELINE_VERSION:
        raise BaselineError(f"baseline {path} is not a version {BASELINE_VERSION} baseline file")
    entries = raw.get("findings")
    if not isinstance(entries, list) or not all(
        isinstance(entry, dict) and isinstance(entry.get("fingerprint"), str) for entry in entries
    ):
        raise BaselineError(f"baseline {path} has a malformed findings list")
    return frozenset(entry["fingerprint"] for entry in entries)


def write_baseline(path: Path, findings: Iterable[Finding]) -> int:
    """Write one entry per distinct finding, sorted so diffs stay small. Returns the count."""
    unique = {f.fingerprint: f for f in findings}
    entries = [
        {"fingerprint": f.fingerprint, "rule_id": f.rule_id, "file": f.file}
        for f in sorted(unique.values(), key=lambda f: (f.file, f.rule_id, f.fingerprint))
    ]
    document = {"version": BASELINE_VERSION, "findings": entries}
    try:
        path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    except OSError as exc:
        raise BaselineError(f"cannot write baseline {path}: {exc.strerror}") from exc
    return len(entries)
