import json
from dataclasses import replace

import pytest

import synthetic as fake
from envguard.config import Config
from envguard.models import Severity
from envguard.reporting import JSON_SCHEMA_VERSION, render_json, render_sarif, render_text
from envguard.rules import RULES, RULES_BY_ID
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


class TestSarif:
    def render(self, result):
        return json.loads(render_sarif(result, "."))

    def test_document_shape(self):
        doc = self.render(ScanResult([], files_scanned=1))
        assert doc["version"] == "2.1.0"
        assert doc["$schema"].endswith("sarif-2.1.0.json")
        (run,) = doc["runs"]
        driver = run["tool"]["driver"]
        assert driver["name"] == "EnvGuard"
        assert driver["version"]
        assert [rule["id"] for rule in driver["rules"]] == [rule.id for rule in RULES]
        assert run["results"] == []

    def test_rules_carry_remediation_and_severity(self):
        driver = self.render(ScanResult([]))["runs"][0]["tool"]["driver"]
        by_id = {rule["id"]: rule for rule in driver["rules"]}
        aws = by_id["aws-access-key"]
        assert aws["help"]["text"] == RULES_BY_ID["aws-access-key"].remediation
        assert aws["defaultConfiguration"]["level"] == "error"
        assert aws["properties"]["security-severity"] == "8.0"
        assert by_id["jwt"]["defaultConfiguration"]["level"] == "warning"

    def test_result_location_rule_reference_and_masking(self):
        key = fake.aws_access_key()
        doc = self.render(make_result(f"KEY={key}"))
        (result,) = doc["runs"][0]["results"]
        rules = doc["runs"][0]["tool"]["driver"]["rules"]
        assert rules[result["ruleIndex"]]["id"] == result["ruleId"] == "aws-access-key"
        assert result["level"] == "error"
        location = result["locations"][0]["physicalLocation"]
        assert location["artifactLocation"]["uri"] == "src/config.py"
        assert location["region"]["startLine"] == 42
        assert result["message"]["text"] == "AWS Access Key: AKIA************"
        assert result["properties"]["confidence"] == 0.95

    def test_output_never_contains_the_secret_or_a_fingerprint(self):
        key = fake.aws_access_key()
        result = make_result(f"KEY={key}")
        text = render_sarif(result, ".")
        assert key not in text
        assert result.findings[0].fingerprint not in text
        assert "partialFingerprints" not in text

    def test_file_names_are_percent_encoded(self):
        result = make_result(f"KEY={fake.aws_access_key()}", path="my dir/é.py")
        uri = self.render(result)["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        assert uri["artifactLocation"]["uri"] == "my%20dir/%C3%A9.py"

    @pytest.mark.parametrize(
        ("severity", "level"),
        [(Severity.HIGH, "error"), (Severity.MEDIUM, "warning"), (Severity.LOW, "note")],
    )
    def test_severity_maps_to_sarif_level(self, severity, level):
        (finding,) = make_result(f"KEY={fake.aws_access_key()}").findings
        result = ScanResult([replace(finding, severity=severity)])
        assert self.render(result)["runs"][0]["results"][0]["level"] == level

    def test_history_findings_name_their_commit(self):
        result = make_result(f"KEY={fake.aws_access_key()}", commit="a" * 40)
        (entry,) = self.render(result)["runs"][0]["results"]
        assert entry["properties"]["commit"] == "a" * 40
        assert "added in commit aaaaaaaa" in entry["message"]["text"]
