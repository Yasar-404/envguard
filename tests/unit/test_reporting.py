import json

import synthetic as fake
from envguard.config import Config
from envguard.reporting import JSON_SCHEMA_VERSION, render_json, render_text
from envguard.rules import RULES
from envguard.scanner import ScanResult, scan_lines


def make_result(secret_line, path="src/config.py", commit=None):
    findings = scan_lines(path, [(42, secret_line)], RULES, Config(), commit)
    return ScanResult(findings, files_scanned=3, files_skipped=1)


def test_json_schema():
    key = fake.aws_access_key()
    report = json.loads(render_json(make_result(f"KEY={key}"), "./project"))
    assert report["version"] == JSON_SCHEMA_VERSION
    assert report["repository"] == "./project"
    assert report["summary"] == {
        "high": 1, "medium": 0, "low": 0, "files_scanned": 3, "files_skipped": 1,
        "baselined": 0,
    }  # fmt: skip
    (finding,) = report["findings"]
    assert list(finding) == [
        "rule_id", "severity", "file", "line", "confidence",
        "masked_value", "message", "remediation", "commit",
    ]  # fmt: skip
    assert finding["rule_id"] == "aws-access-key"
    assert finding["severity"] == "high"
    assert finding["file"] == "src/config.py"
    assert finding["line"] == 42
    assert finding["commit"] is None


def test_reports_never_contain_the_secret():
    key = fake.aws_access_key()
    result = make_result(f"KEY={key}")
    assert key not in render_json(result, ".")
    assert key not in render_text(result, ".")


def test_json_for_clean_scan_has_empty_findings():
    report = json.loads(render_json(ScanResult([], 5, 0), "."))
    assert report["findings"] == []
    assert report["summary"]["high"] == 0


def test_json_includes_commit_for_history_findings():
    result = make_result(f"KEY={fake.aws_access_key()}", commit="a" * 40)
    assert json.loads(render_json(result, "."))["findings"][0]["commit"] == "a" * 40


def test_text_report_layout():
    text = render_text(make_result(f"KEY={fake.aws_access_key()}"), "./project")
    lines = text.splitlines()
    assert lines[0] == "EnvGuard Security Scanner"
    assert "Scanning: ./project" in lines
    assert lines[4:7] == ["1 HIGH", "0 MEDIUM", "0 LOW"]
    assert "HIGH   AWS Access Key" in lines
    assert "       src/config.py:42" in lines
    assert "       Confidence: 95%" in lines
    assert "       Value: AKIA************" in lines
    assert "       Recommendation:" in lines
    assert lines[-1] == "Scanned 3 files (1 skipped: binary, too large or unreadable)."


def test_text_report_shortens_commit_hashes():
    result = make_result(f"KEY={fake.aws_access_key()}", commit="0123456789abcdef" * 2)
    assert "src/config.py:42 (commit 01234567)" in render_text(result, ".")


def test_text_report_for_clean_scan():
    text = render_text(ScanResult([], 12, 0), ".")
    assert "0 HIGH" in text
    assert text.endswith("No secrets found. Scanned 12 files.")


def test_text_report_aligns_multi_word_severities():
    result = make_result(f'db_password = "{fake.synthetic(12, "pw")}"')
    assert "MEDIUM Hardcoded Password" in render_text(result, ".").splitlines()
