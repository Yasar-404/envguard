from __future__ import annotations

import json
import textwrap
from collections import Counter
from typing import Any
from urllib.parse import quote

from envguard import __version__
from envguard.models import Finding, Severity
from envguard.rules import RULES, Rule
from envguard.scanner import ScanResult

JSON_SCHEMA_VERSION = "1"
_LABEL_WIDTH = len("MEDIUM") + 1

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_SARIF_LEVEL = {Severity.HIGH: "error", Severity.MEDIUM: "warning", Severity.LOW: "note"}
# GitHub code scanning ranks security alerts by this CVSS-like score.
_SARIF_SECURITY_SEVERITY = {Severity.HIGH: "8.0", Severity.MEDIUM: "5.0", Severity.LOW: "2.0"}


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


def render_sarif(result: ScanResult, _target: str) -> str:
    """SARIF 2.1.0 for code-scanning tools such as GitHub. Contains only masked values."""
    rule_index = {rule.id: index for index, rule in enumerate(RULES)}
    document: dict[str, Any] = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "EnvGuard",
                        "version": __version__,
                        "rules": [_sarif_rule(rule) for rule in RULES],
                    }
                },
                "results": [_sarif_result(f, rule_index[f.rule_id]) for f in result.findings],
            }
        ],
    }
    return json.dumps(document, indent=2)


def _sarif_rule(rule: Rule) -> dict[str, Any]:
    return {
        "id": rule.id,
        "name": rule.name,
        "shortDescription": {"text": rule.name},
        "fullDescription": {"text": rule.description},
        "help": {"text": rule.remediation},
        "defaultConfiguration": {"level": _SARIF_LEVEL[rule.severity]},
        "properties": {
            "tags": ["security", "secret"],
            "security-severity": _SARIF_SECURITY_SEVERITY[rule.severity],
        },
    }


def _sarif_result(finding: Finding, rule_index: int) -> dict[str, Any]:
    text = f"{finding.message}: {finding.masked_value}"
    if finding.commit:
        text += f" (added in commit {finding.commit[:8]})"
    properties: dict[str, Any] = {
        "confidence": finding.confidence,
        "maskedValue": finding.masked_value,
    }
    if finding.commit:
        properties["commit"] = finding.commit
    return {
        "ruleId": finding.rule_id,
        "ruleIndex": rule_index,
        "level": _SARIF_LEVEL[finding.severity],
        "message": {"text": text},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": quote(finding.file, safe="/")},
                    "region": {"startLine": max(finding.line, 1)},
                }
            }
        ],
        "properties": properties,
    }


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
