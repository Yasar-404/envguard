import dataclasses

import synthetic as fake
from envguard.config import Config
from envguard.models import Severity
from envguard.rules import RULES
from envguard.scanner import (
    IGNORE_MARKER,
    MAX_LINE_LENGTH,
    active_rules,
    classify,
    scan_lines,
    scan_tree,
)
from repo import write_tree


def scan_text(text, path="app/settings.py", config=None):
    lines = enumerate(text.split("\n"), 1)
    return scan_lines(path, lines, RULES, config or Config())


def test_reports_rule_line_and_masked_value():
    key = fake.aws_access_key()
    (finding,) = scan_text(f"import os\n\nAWS_ACCESS_KEY_ID = '{key}'\n")
    assert finding.rule_id == "aws-access-key"
    assert finding.line == 3
    assert finding.file == "app/settings.py"
    assert key not in finding.masked_value
    assert key not in repr(finding)


def test_findings_never_contain_the_secret_in_any_field():
    secret = fake.stripe_key()
    (finding,) = scan_text(f'STRIPE = "{secret}"')
    assert all(secret not in str(value) for value in dataclasses.astuple(finding))


def test_inline_marker_suppresses_a_finding():
    assert scan_text(f"KEY={fake.aws_access_key()}  # {IGNORE_MARKER}") == []


def test_overlong_lines_are_skipped():
    line = fake.aws_access_key() + " " + "a" * MAX_LINE_LENGTH
    assert scan_text(line) == []


def test_overlapping_rules_yield_a_single_finding():
    # Matches both the aws-secret-key and generic-secret rules.
    secret = fake.aws_secret_key()
    findings = scan_text(f"aws_secret_key = '{secret}'")
    assert [f.rule_id for f in findings] == ["aws-secret-key"]


def test_disabled_rules_are_not_active():
    config = Config(disable_rules=frozenset({"jwt"}))
    assert "jwt" not in {rule.id for rule in active_rules(config)}
    assert scan_lines("a.py", [(1, f"t = '{fake.jwt()}'")], active_rules(config), config) == []


class TestSeverity:
    def test_full_confidence_keeps_rule_severity(self):
        assert classify(Severity.HIGH, 0.95) is Severity.HIGH

    def test_low_confidence_lowers_severity_one_level(self):
        assert classify(Severity.HIGH, 0.55) is Severity.MEDIUM
        assert classify(Severity.MEDIUM, 0.55) is Severity.LOW

    def test_never_drops_below_low(self):
        assert classify(Severity.LOW, 0.1) is Severity.LOW

    def test_min_severity_filters_findings(self):
        text = f"KEY={fake.aws_access_key()}\nclient_secret = '{fake.generic_secret()}'"
        assert len(scan_text(text)) == 2
        high_only = scan_text(text, config=Config(min_severity=Severity.HIGH))
        assert [f.rule_id for f in high_only] == ["aws-access-key"]


class TestConfidence:
    line = f'db_password = "{fake.synthetic(12, "pw")}"'

    def test_min_confidence_filters_weak_matches(self):
        assert scan_text(self.line)
        assert scan_text(self.line, config=Config(min_confidence=0.95)) == []

    def test_test_directories_lower_confidence(self):
        (app,) = scan_text(self.line, path="src/app.py")
        (test,) = scan_text(self.line, path="tests/test_app.py", config=Config(min_confidence=0.1))
        assert test.confidence < app.confidence

    def test_template_files_lower_confidence(self):
        (real,) = scan_text(self.line, path="config.py")
        (sample,) = scan_text(
            self.line, path="config.py.example", config=Config(min_confidence=0.1)
        )
        assert sample.confidence < real.confidence

    def test_env_files_raise_confidence(self):
        (plain,) = scan_text(self.line, path="config.txt")
        (dotenv,) = scan_text(self.line, path=".env")
        assert dotenv.confidence > plain.confidence

    def test_confidence_is_capped_at_one(self):
        (finding,) = scan_text(f"KEY={fake.github_token()}", path=".env")
        assert finding.confidence <= 1.0


class TestScanTree:
    def test_skips_binary_oversized_and_undecodable_files_without_failing(self, tmp_path):
        key = fake.aws_access_key()
        write_tree(
            tmp_path,
            {
                "logo.png": b"\x89PNG\r\n\x1a\n" + b"\x00" * 64,
                "data.dat": b"AKIA\x00" + key.encode(),
                "huge.txt": f"KEY={key}\n" + "x" * 3000,
                "bad.txt": b"\xff\xfe\xfa junk \x80\x81 then KEY=" + key.encode() + b"\n",
                "ok.txt": f"KEY={key}\n",
            },
        )
        result = scan_tree(tmp_path, Config(max_file_size=2048))
        assert [f.file for f in result.findings] == ["bad.txt", "ok.txt"]
        assert result.files_scanned == 2
        assert result.files_skipped == 2  # data.dat (binary) and huge.txt (too large)

    def test_scans_a_single_file(self, tmp_path):
        write_tree(tmp_path, {"one.env": f"KEY={fake.aws_access_key()}\n"})
        result = scan_tree(tmp_path / "one.env", Config())
        assert [f.file for f in result.findings] == ["one.env"]

    def test_findings_are_ordered_by_severity_then_location(self, tmp_path):
        write_tree(
            tmp_path,
            {
                "b.py": f"KEY={fake.aws_access_key()}\n",
                "a.py": f"client_secret = '{fake.generic_secret()}'\nKEY={fake.aws_access_key()}\n",
            },
        )
        result = scan_tree(tmp_path, Config())
        assert [(f.file, f.line) for f in result.findings] == [
            ("a.py", 2),
            ("b.py", 1),
            ("a.py", 1),
        ]
