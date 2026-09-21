import json
import shutil

import pytest

import synthetic as fake
from envguard.cli import main
from repo import commit_all, init_repo, write_tree


def run(capsys, *argv):
    code = main(list(argv))
    out, err = capsys.readouterr()
    return code, out, err


def scan_json(capsys, path, *args):
    code, out, err = run(capsys, "scan", str(path), "--json", *map(str, args))
    return code, json.loads(out) if out else None, err


@pytest.fixture
def baseline_path(tmp_path_factory):
    return tmp_path_factory.mktemp("baseline") / "baseline.json"


def test_baseline_accepts_existing_findings_and_reports_only_new_ones(
    leaky_project, baseline_path, capsys
):
    code, out, err = run(capsys, "scan", str(leaky_project), "--write-baseline", str(baseline_path))
    assert (code, out) == (0, "")
    assert "Wrote 3 finding(s)" in err

    code, report, _ = scan_json(capsys, leaky_project, "--baseline", baseline_path)
    assert code == 0
    assert report["findings"] == []
    assert report["summary"]["baselined"] == 3

    new_key = "AKIA" + fake.synthetic(16, "new-key", fake.UPPER_DIGITS)
    write_tree(leaky_project, {"src/new.py": f'KEY = "{new_key}"\n'})
    code, report, _ = scan_json(capsys, leaky_project, "--baseline", baseline_path)
    assert code == 1
    assert [f["file"] for f in report["findings"]] == ["src/new.py"]


def test_moving_a_baselined_secret_does_not_resurface_it(leaky_project, baseline_path, capsys):
    run(capsys, "scan", str(leaky_project), "--write-baseline", str(baseline_path))
    config = leaky_project / "src" / "config.py"
    config.write_text("# header\n\n" + config.read_text(encoding="utf-8"), encoding="utf-8")
    code, _, _ = scan_json(capsys, leaky_project, "--baseline", baseline_path)
    assert code == 0


def test_text_output_mentions_suppressed_findings(leaky_project, baseline_path, capsys):
    run(capsys, "scan", str(leaky_project), "--write-baseline", str(baseline_path))
    _, out, _ = run(capsys, "scan", str(leaky_project), "--baseline", str(baseline_path))
    assert "3 known finding(s) suppressed by baseline." in out


def test_baseline_in_config_is_relative_to_the_config_file(leaky_project, capsys):
    baseline = leaky_project / "ci" / "known.json"
    baseline.parent.mkdir()
    run(capsys, "scan", str(leaky_project), "--write-baseline", str(baseline))
    (leaky_project / ".envguard.toml").write_text('baseline = "ci/known.json"\n')
    code, report, _ = scan_json(capsys, leaky_project)
    assert code == 0
    assert report["summary"]["baselined"] == 3


def test_baseline_and_write_baseline_conflict(clean_project, capsys):
    code, _, err = run(
        capsys, "scan", str(clean_project), "--baseline", "a.json", "--write-baseline", "b.json"
    )
    assert code == 2
    assert "cannot be used together" in err


def test_missing_baseline_file_exits_with_2(clean_project, tmp_path, capsys):
    code, _, err = run(capsys, "scan", str(clean_project), "--baseline", str(tmp_path / "x.json"))
    assert code == 2
    assert "cannot read baseline" in err


@pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")
class TestHistory:
    KEY = fake.aws_access_key()

    def leak_then_remove(self, repo, *keys):
        init_repo(repo)
        write_tree(repo, {"a.py": "".join(f"K{i} = '{k}'\n" for i, k in enumerate(keys))})
        commit_all(repo)
        write_tree(repo, {"a.py": "x = 1\n"})
        commit_all(repo)

    def test_distinct_secrets_sharing_a_mask_are_both_reported(self, tmp_path, capsys):
        other = "AKIA" + fake.synthetic(16, "history-other", fake.UPPER_DIGITS)
        self.leak_then_remove(tmp_path, self.KEY, other)
        _, report, _ = scan_json(capsys, tmp_path, "--history")
        assert sorted(f["line"] for f in report["findings"]) == [1, 2]

    def test_baseline_covers_history_findings(self, tmp_path, baseline_path, capsys):
        self.leak_then_remove(tmp_path, self.KEY)
        run(capsys, "scan", str(tmp_path), "--history", "--write-baseline", str(baseline_path))
        code, report, _ = scan_json(capsys, tmp_path, "--history", "--baseline", baseline_path)
        assert code == 0
        assert report["summary"]["baselined"] == 1
