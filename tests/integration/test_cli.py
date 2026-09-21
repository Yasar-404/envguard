import json
import subprocess
import sys

import pytest

import synthetic as fake
from envguard import __version__
from envguard.cli import main
from repo import write_tree


def run(capsys, *argv):
    code = main(list(argv))
    out, err = capsys.readouterr()
    return code, out, err


def test_findings_exit_with_1(leaky_project, capsys):
    code, out, err = run(capsys, "scan", str(leaky_project))
    assert code == 1
    assert "AWS Access Key" in out
    assert "Stripe Live Secret Key" in out
    assert err == ""


def test_clean_project_exits_with_0(clean_project, capsys):
    code, out, _ = run(capsys, "scan", str(clean_project))
    assert code == 0
    assert "No secrets found." in out


def test_missing_path_exits_with_2(tmp_path, capsys):
    code, out, err = run(capsys, "scan", str(tmp_path / "missing"))
    assert code == 2
    assert out == ""
    assert "path does not exist" in err


def test_invalid_config_exits_with_2(clean_project, capsys):
    (clean_project / ".envguard.toml").write_text("bogus = 1\n")
    code, _, err = run(capsys, "scan", str(clean_project))
    assert code == 2
    assert "unknown option" in err


def test_bad_arguments_exit_with_2(capsys):
    with pytest.raises(SystemExit) as raised:
        main(["scan", "--severity", "critical"])
    assert raised.value.code == 2


def test_no_command_prints_help_and_exits_with_2(capsys):
    code, out, err = run(capsys)
    assert code == 2
    assert "usage: envguard" in err


def test_history_outside_a_repository_exits_with_2(clean_project, capsys):
    code, _, err = run(capsys, "scan", str(clean_project), "--history")
    assert code == 2
    assert "git" in err


def test_max_commits_requires_history(clean_project, capsys):
    code, _, err = run(capsys, "scan", str(clean_project), "--max-commits", "5")
    assert code == 2
    assert "--history" in err


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as raised:
        main(["--version"])
    assert raised.value.code == 0
    assert capsys.readouterr().out.strip() == f"envguard {__version__}"


def test_help_documents_exit_codes(capsys):
    with pytest.raises(SystemExit):
        main(["scan", "--help"])
    out = capsys.readouterr().out
    assert "exit codes:" in out
    assert "--history" in out


def test_json_output_is_valid_and_masked(leaky_project, capsys):
    code, out, _ = run(capsys, "scan", str(leaky_project), "--json")
    report = json.loads(out)
    assert code == 1
    assert report["version"] == "1"
    assert report["summary"]["high"] >= 2
    files = {f["file"] for f in report["findings"]}
    assert files == {"src/config.py", "deploy/.env"}
    for secret in (fake.aws_access_key(), fake.stripe_key(), fake.generic_secret()):
        assert secret not in out


def test_text_output_never_contains_secrets(leaky_project, capsys):
    _, out, err = run(capsys, "scan", str(leaky_project))
    for secret in (fake.aws_access_key(), fake.stripe_key(), fake.generic_secret()):
        assert secret not in out + err


def test_lockfiles_binaries_and_dependencies_are_skipped_by_default(leaky_project, capsys):
    write_tree(leaky_project, {"node_modules/dep/index.js": f"K={fake.aws_access_key()}\n"})
    _, out, _ = run(capsys, "scan", str(leaky_project), "--json")
    assert {f["file"] for f in json.loads(out)["findings"]} == {"src/config.py", "deploy/.env"}


def test_severity_option_filters_findings(leaky_project, capsys):
    _, out, _ = run(capsys, "scan", str(leaky_project), "--json", "--severity", "high")
    findings = json.loads(out)["findings"]
    assert findings and {f["severity"] for f in findings} == {"high"}
    assert "deploy/.env" not in {f["file"] for f in findings}


def test_exclude_option_can_clear_all_findings(leaky_project, capsys):
    code, _, _ = run(capsys, "scan", str(leaky_project), "--exclude", "src/", "--exclude", ".env")
    assert code == 0


def test_scanning_a_subdirectory_reports_paths_relative_to_it(leaky_project, capsys):
    _, out, _ = run(capsys, "scan", str(leaky_project / "src"), "--json")
    assert {f["file"] for f in json.loads(out)["findings"]} == {"config.py"}


def test_config_file_is_discovered_and_applied(leaky_project, capsys):
    (leaky_project / ".envguard.toml").write_text(
        'exclude = ["deploy/"]\ndisable_rules = ["stripe-secret-key"]\n', encoding="utf-8"
    )
    _, out, _ = run(capsys, "scan", str(leaky_project), "--json")
    findings = json.loads(out)["findings"]
    assert {f["rule_id"] for f in findings} == {"aws-access-key"}


def test_explicit_config_option(leaky_project, tmp_path_factory, capsys):
    config = tmp_path_factory.mktemp("cfg") / "custom.toml"
    config.write_text('min_severity = "high"\n', encoding="utf-8")
    _, out, _ = run(capsys, "scan", str(leaky_project), "--json", "--config", str(config))
    assert {f["severity"] for f in json.loads(out)["findings"]} == {"high"}


def test_rules_command_lists_every_rule(capsys):
    code, out, _ = run(capsys, "rules")
    assert code == 0
    assert "aws-access-key" in out and "password-assignment" in out


def test_installed_entry_point_via_python_dash_m(clean_project):
    proc = subprocess.run(
        [sys.executable, "-m", "envguard", "scan", str(clean_project)],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0
    assert "EnvGuard Security Scanner" in proc.stdout
