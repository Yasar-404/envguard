from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable
from dataclasses import dataclass, replace
from functools import lru_cache
from itertools import groupby
from pathlib import Path, PurePosixPath

from envguard import git
from envguard.config import Config
from envguard.filesystem import (
    PathMatcher,
    discover_files,
    exclude_patterns,
    is_scannable_name,
    read_text,
)
from envguard.models import EnvGuardError, Finding, Severity
from envguard.rules import RULES, Hit, Rule

# Longer lines are minified bundles or data blobs; scanning them is slow and rarely useful.
MAX_LINE_LENGTH = 2000
IGNORE_MARKER = "envguard:ignore"
# Findings below this confidence are reported one severity level lower.
LOW_CONFIDENCE = 0.6

_LOW_TRUST_DIRS = frozenset(
    {
        "test",
        "tests",
        "__tests__",
        "spec",
        "fixtures",
        "testdata",
        "example",
        "examples",
        "doc",
        "docs",
    }
)
_TEMPLATE_SUFFIXES = (".example", ".sample", ".template", ".dist", ".md", ".rst")


@dataclass(frozen=True)
class ScanResult:
    findings: list[Finding]
    files_scanned: int = 0
    files_skipped: int = 0
    baselined: int = 0


def active_rules(config: Config) -> tuple[Rule, ...]:
    return tuple(rule for rule in RULES if rule.id not in config.disable_rules)


def scan(
    root: Path,
    config: Config,
    *,
    history: bool = False,
    max_commits: int | None = None,
    baseline: frozenset[str] = frozenset(),
) -> ScanResult:
    if not root.exists():
        raise EnvGuardError(f"path does not exist: {root}")
    result = scan_tree(root, config)
    if history:
        current = {f.fingerprint for f in result.findings}
        past = [f for f in scan_history(root, config, max_commits) if f.fingerprint not in current]
        result = replace(result, findings=_ordered(result.findings + past))
    if not baseline:
        return result
    kept = [f for f in result.findings if f.fingerprint not in baseline]
    return replace(result, findings=kept, baselined=len(result.findings) - len(kept))


def scan_tree(root: Path, config: Config) -> ScanResult:
    rules = active_rules(config)
    if root.is_file():
        base, paths = root.parent, [root.name]
    else:
        base, paths = root, list(discover_files(root, exclude_patterns(config.exclude)))

    findings: list[Finding] = []
    scanned = skipped = 0
    for path in paths:
        text = read_text(base / path, config.max_file_size)
        if text is None:
            skipped += 1
            continue
        scanned += 1
        findings += scan_lines(path, enumerate(text.split("\n"), 1), rules, config)
    return ScanResult(_ordered(findings), scanned, skipped)


def scan_history(root: Path, config: Config, max_commits: int | None = None) -> list[Finding]:
    """Findings in lines added by past commits, reported once at the commit that added them."""
    if root.is_file():
        raise EnvGuardError("--history needs a directory inside a git repository, not a file")
    git.require_repository(root)
    rules = active_rules(config)
    matcher = PathMatcher(exclude_patterns(config.exclude))
    skip: dict[str, bool] = {}

    def should_skip(path: str) -> bool:
        if path not in skip:
            skip[path] = not is_scannable_name(path) or matcher.excludes_path(path)
        return skip[path]

    # Commits arrive newest first, so a later duplicate is an earlier introduction.
    introduced: dict[str, Finding] = {}
    for (commit, path), lines in groupby(git.added_lines(root, max_commits), lambda a: a[:2]):
        if should_skip(path):
            continue
        numbered = ((line.number, line.text) for line in lines)
        for finding in scan_lines(path, numbered, rules, config, commit):
            introduced[finding.fingerprint] = finding
    return list(introduced.values())


def scan_lines(
    path: str,
    lines: Iterable[tuple[int, str]],
    rules: Iterable[Rule],
    config: Config,
    commit: str | None = None,
) -> list[Finding]:
    rules = tuple(rules)
    if not rules:
        return []
    has_trigger = _line_trigger(rules).search
    weight, bonus = _path_weight(path)
    findings: list[Finding] = []
    for number, line in lines:
        if len(line) > MAX_LINE_LENGTH:
            continue
        lowered = line.lower()
        # One C-level search rejects nearly every line before any per-rule work happens.
        if not has_trigger(lowered) or IGNORE_MARKER in line:
            continue
        hits = [hit for rule in rules for hit in rule.find(line, lowered)]
        for hit in _without_overlaps(hits):
            confidence = min(1.0, hit.confidence * weight + bonus)
            severity = classify(hit.rule.severity, confidence)
            if confidence < config.min_confidence or severity < config.min_severity:
                continue
            findings.append(
                Finding(
                    rule_id=hit.rule.id,
                    severity=severity,
                    file=path,
                    line=number,
                    confidence=round(confidence, 2),
                    masked_value=hit.masked,
                    message=hit.rule.name,
                    remediation=hit.rule.remediation,
                    commit=commit,
                    fingerprint=_fingerprint(hit.rule.id, path, hit.digest),
                )
            )
    return findings


@lru_cache(maxsize=4)
def _line_trigger(rules: tuple[Rule, ...]) -> re.Pattern[str]:
    words = sorted({keyword for rule in rules for keyword in rule.keywords})
    return re.compile("|".join(map(re.escape, words)))


def classify(rule_severity: Severity, confidence: float) -> Severity:
    return rule_severity.lowered() if confidence < LOW_CONFIDENCE else rule_severity


def _path_weight(path: str) -> tuple[float, float]:
    """Multiplier and bonus applied to confidence based on where the file lives."""
    pure = PurePosixPath(path.lower())
    if _LOW_TRUST_DIRS.intersection(pure.parts[:-1]) or pure.name.endswith(_TEMPLATE_SUFFIXES):
        return 0.7, 0.0
    if pure.name.startswith(".env"):
        return 1.0, 0.1
    return 1.0, 0.0


def _without_overlaps(hits: list[Hit]) -> list[Hit]:
    """Keep the strongest hit where several rules matched the same characters."""
    if len(hits) < 2:
        return hits
    kept: list[Hit] = []
    for hit in sorted(hits, key=lambda h: (-h.rule.severity, -h.confidence)):
        if all(hit.end <= other.start or hit.start >= other.end for other in kept):
            kept.append(hit)
    return kept


def _fingerprint(rule_id: str, path: str, secret_digest: str) -> str:
    """Stable across line moves; changes when the rule, the file or the secret changes."""
    return hashlib.sha256(f"{rule_id}\0{path}\0{secret_digest}".encode()).hexdigest()[:32]


def _ordered(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (-f.severity, f.file, f.line, f.rule_id, f.commit or ""))
