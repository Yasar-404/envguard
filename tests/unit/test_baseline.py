import json

import pytest

import synthetic as fake
from envguard.baseline import BaselineError, load_baseline, write_baseline
from envguard.config import Config
from envguard.reporting import render_json, render_text
from envguard.rules import RULES
from envguard.scanner import ScanResult, scan_lines


def findings_for(text, path="src/app.py"):
    return scan_lines(path, enumerate(text.split("\n"), 1), RULES, Config())


def other_key():
    return "AKIA" + fake.synthetic(16, "other", fake.UPPER_DIGITS)


def test_fingerprint_survives_moving_the_line():
    key = fake.aws_access_key()
    (before,) = findings_for(f"K = '{key}'")
    (after,) = findings_for(f"# a new comment\n\nK = '{key}'")
    assert before.line != after.line
    assert before.fingerprint == after.fingerprint


def test_fingerprint_differs_for_another_secret_with_the_same_mask():
    (a,) = findings_for(f"K = '{fake.aws_access_key()}'")
    (b,) = findings_for(f"K = '{other_key()}'")
    assert a.masked_value == b.masked_value
    assert a.fingerprint != b.fingerprint


def test_fingerprint_differs_across_files():
    line = f"K = '{fake.aws_access_key()}'"
    (a,) = findings_for(line, "a.py")
    (b,) = findings_for(line, "b.py")
    assert a.fingerprint != b.fingerprint


def test_fingerprint_does_not_contain_the_secret():
    key = fake.aws_access_key()
    (finding,) = findings_for(f"K = '{key}'")
    assert len(finding.fingerprint) == 32
    assert key not in finding.fingerprint
    assert finding.fingerprint not in repr(finding)


def test_round_trip_is_sorted_and_deduplicated(tmp_path):
    key = fake.aws_access_key()
    found = findings_for(f"A = '{key}'\nB = '{key}'", "z.py") + findings_for(f"A = '{key}'", "a.py")
    path = tmp_path / "baseline.json"
    assert write_baseline(path, found) == 2

    document = json.loads(path.read_text(encoding="utf-8"))
    assert document["version"] == "1"
    assert [entry["file"] for entry in document["findings"]] == ["a.py", "z.py"]
    assert load_baseline(path) == {f.fingerprint for f in found}


def test_written_baseline_contains_no_secret(tmp_path):
    key = fake.aws_access_key()
    path = tmp_path / "baseline.json"
    write_baseline(path, findings_for(f"K = '{key}'"))
    assert key not in path.read_text(encoding="utf-8")


def test_empty_baseline_is_valid(tmp_path):
    path = tmp_path / "baseline.json"
    assert write_baseline(path, []) == 0
    assert load_baseline(path) == frozenset()


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("not json", "not valid JSON"),
        ("[]", "version 1"),
        ('{"version": "2", "findings": []}', "version 1"),
        ('{"version": "1"}', "malformed"),
        ('{"version": "1", "findings": [{"rule_id": "x"}]}', "malformed"),
        ('{"version": "1", "findings": ["abc"]}', "malformed"),
    ],
)
def test_invalid_baselines_are_rejected(tmp_path, content, message):
    path = tmp_path / "baseline.json"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(BaselineError, match=message):
        load_baseline(path)


def test_missing_baseline_is_an_error(tmp_path):
    with pytest.raises(BaselineError, match="cannot read"):
        load_baseline(tmp_path / "nope.json")


def test_unwritable_baseline_path_is_an_error(tmp_path):
    with pytest.raises(BaselineError, match="cannot write"):
        write_baseline(tmp_path / "missing-dir" / "baseline.json", [])


def test_baselined_findings_are_counted_in_both_report_formats():
    result = ScanResult([], files_scanned=4, baselined=2)
    assert json.loads(render_json(result, "."))["summary"]["baselined"] == 2
    assert "2 known finding(s) suppressed by baseline." in render_text(result, ".")
