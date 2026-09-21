from __future__ import annotations

import json
import textwrap
from collections import Counter

from envguard.models import Finding, Severity
from envguard.scanner import ScanResult

JSON_SCHEMA_VERSION = "1"
_LABEL_WIDTH = len("MEDIUM") + 1


def render_json(result: ScanResult, target: str) -> str:
    counts = _counts(result.findings)
    payload = {
        "version": JSON_SCHEMA_VERSION,
        "repository": target,
        "summary": {
            "high": counts[Severity.HIGH],
            "medium": counts[Severity.MEDIUM],
            "low": counts[Severity.LOW],
            "files_scanned": result.files_scanned,
            "files_skipped": result.files_skipped,
            "baselined": result.baselined,
        },
        "findings": [
            {
                "rule_id": f.rule_id,
                "severity": f.severity.label,
                "file": f.file,
                "line": f.line,
                "confidence": f.confidence,
                "masked_value": f.masked_value,
                "message": f.message,
                "remediation": f.remediation,
                "commit": f.commit,
            }
            for f in result.findings
        ],
    }
    return json.dumps(payload, indent=2)


def render_text(result: ScanResult, target: str) -> str:
    counts = _counts(result.findings)
    lines = ["EnvGuard Security Scanner", "", f"Scanning: {target}", ""]
    lines += [f"{counts[severity]} {severity.name}" for severity in reversed(Severity)]
    for finding in result.findings:
        lines += ["", *_finding_block(finding)]
    lines += ["", _footer(result)]
    return "\n".join(lines)


def _finding_block(finding: Finding) -> list[str]:
    indent = " " * _LABEL_WIDTH
    location = f"{finding.file}:{finding.line}"
    if finding.commit:
        location += f" (commit {finding.commit[:8]})"
    block = [
        f"{finding.severity.name:<{_LABEL_WIDTH}}{finding.message}",
        f"{indent}{location}",
        f"{indent}Confidence: {round(finding.confidence * 100)}%",
        f"{indent}Value: {finding.masked_value}",
        "",
        f"{indent}Recommendation:",
    ]
    block += textwrap.wrap(
        finding.remediation, width=78, initial_indent=indent, subsequent_indent=indent
    )
    return block


def _footer(result: ScanResult) -> str:
    summary = "" if result.findings else "No secrets found. "
    summary += f"Scanned {result.files_scanned} files"
    if result.files_skipped:
        summary += f" ({result.files_skipped} skipped: binary, too large or unreadable)"
    summary += "."
    if result.baselined:
        summary += f" {result.baselined} known finding(s) suppressed by baseline."
    return summary


def _counts(findings: list[Finding]) -> Counter[Severity]:
    return Counter(f.severity for f in findings)
