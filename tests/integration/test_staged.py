import json
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest

import synthetic as fake
from envguard.cli import main
from repo import commit_all, git, init_repo, write_tree

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")

KEY = fake.aws_access_key()


@pytest.fixture
def repo(tmp_path):
    init_repo(tmp_path)
    return tmp_path


def staged_scan(capsys, path, *args):
    code = main(["scan", str(path), "--staged", "--json", *map(str, args)])
    out, err = capsys.readouterr()
    return code, json.loads(out) if out else None, err


def test_staged_secret_is_reported_with_its_line_number(repo, capsys):
    write_tree(repo, {"config.py": f"import os\n\nAWS = '{KEY}'\n"})
    git(repo, "add", "config.py")
    code, report, _ = staged_scan(capsys, repo)
    assert code == 1
    (finding,) = report["findings"]
    assert (finding["file"], finding["line"], finding["commit"]) == ("config.py", 3, None)
    assert report["summary"]["files_scanned"] == 1
    assert KEY not in json.dumps(report)


def test_unstaged_secrets_are_ignored(repo, capsys):
    write_tree(repo, {"a.py": "x = 1\n", "b.py": f"K = '{KEY}'\n"})
    git(repo, "add", "a.py")
    code, report, _ = staged_scan(capsys, repo)
    assert code == 0
    assert report["findings"] == []


def test_the_index_is_scanned_not_the_working_tree(repo, capsys):
    write_tree(repo, {"a.py": f"K = '{KEY}'\n"})
    git(repo, "add", "a.py")
    write_tree(repo, {"a.py": "K = None\n"})  # fixed on disk, but the leak is still staged
    code, _, _ = staged_scan(capsys, repo)
    assert code == 1

    git(repo, "add", "a.py")
    code, _, _ = staged_scan(capsys, repo)
    assert code == 0


def test_only_lines_added_by_the_change_are_scanned(repo, capsys):
    other = "AKIA" + fake.synthetic(16, "existing", fake.UPPER_DIGITS)
    write_tree(repo, {"a.py": f"OLD = '{other}'\nx = 1\n"})
    commit_all(repo)
    write_tree(repo, {"a.py": f"OLD = '{other}'\nx = 1\nNEW = '{KEY}'\n"})
    git(repo, "add", "a.py")
    _, report, _ = staged_scan(capsys, repo)
    assert [f["line"] for f in report["findings"]] == [3]


def test_nothing_staged_is_clean(repo, capsys):
    write_tree(repo, {"a.py": f"K = '{KEY}'\n"})
    code, report, _ = staged_scan(capsys, repo)
    assert code == 0
    assert report["summary"]["files_scanned"] == 0


def test_excludes_binary_extensions_and_inline_markers_apply(repo, capsys):
    write_tree(
        repo,
        {
            "fixtures/a.py": f"K = '{KEY}'\n",
            "logo.png": f"K={KEY}\n",
            "b.py": f"K = '{KEY}'  # envguard:ignore\n",
        },
    )
    git(repo, "add", "-A")
    code, _, _ = staged_scan(capsys, repo, "--exclude", "fixtures/")
    assert code == 0


def test_baseline_applies_to_staged_findings(repo, capsys, tmp_path_factory):
    write_tree(repo, {"a.py": f"K = '{KEY}'\n"})
    git(repo, "add", "a.py")
    baseline = tmp_path_factory.mktemp("baseline") / "baseline.json"
    main(["scan", str(repo), "--staged", "--write-baseline", str(baseline)])
    capsys.readouterr()
    code, report, _ = staged_scan(capsys, repo, "--baseline", baseline)
    assert code == 0
    assert report["summary"]["baselined"] == 1


def test_paths_are_relative_to_the_scanned_subdirectory(repo, capsys):
    write_tree(repo, {"svc/a.py": f"K = '{KEY}'\n", "other/b.py": f"K = '{KEY}'\n"})
    git(repo, "add", "-A")
    _, report, _ = staged_scan(capsys, repo / "svc")
    assert [f["file"] for f in report["findings"]] == ["a.py"]


def test_staged_cannot_be_combined_with_history(repo, capsys):
    code, _, err = staged_scan(capsys, repo, "--history")
    assert code == 2
    assert "cannot be used together" in err


def test_staged_outside_a_repository_is_an_error(tmp_path, capsys):
    code, _, err = staged_scan(capsys, tmp_path)
    assert code == 2
    assert "--staged requires" in err


def test_staged_rejects_a_single_file(repo, capsys):
    write_tree(repo, {"a.py": "x = 1\n"})
    code, _, err = staged_scan(capsys, repo / "a.py")
    assert code == 2
    assert "directory" in err


def install_hook(repo: Path) -> None:
    python = Path(sys.executable).as_posix()
    hook = repo / ".git" / "hooks" / "pre-commit"
    hook.write_text(f'#!/bin/sh\nexec "{python}" -m envguard scan --staged\n', newline="\n")
    hook.chmod(hook.stat().st_mode | stat.S_IEXEC)


def try_commit(repo: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "git", "-C", str(repo),
            "-c", "user.name=EnvGuard Tests", "-c", "user.email=tests@envguard.invalid",
            "-c", "commit.gpgsign=false",
            "commit", "-m", "change",
        ],
        capture_output=True,
        text=True,
    )  # fmt: skip


def test_plain_git_hook_blocks_a_commit_containing_a_secret(repo):
    install_hook(repo)
    write_tree(repo, {"config.py": f"K = '{KEY}'\n"})
    git(repo, "add", "config.py")

    result = try_commit(repo)
    assert result.returncode != 0
    output = result.stdout + result.stderr  # git shows a hook's stdout on stderr
    assert "AWS Access Key" in output
    assert KEY not in output
    assert (
        subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True
        ).returncode
        != 0
    )


def test_plain_git_hook_allows_a_clean_commit(repo):
    install_hook(repo)
    write_tree(repo, {"main.py": "print('hello')\n"})
    git(repo, "add", "main.py")
    assert try_commit(repo).returncode == 0


def test_hook_manifest_runs_the_staged_scan_without_filenames():
    manifest = (Path(__file__).resolve().parents[2] / ".pre-commit-hooks.yaml").read_text()
    assert "id: envguard" in manifest
    assert "entry: envguard scan --staged" in manifest
    assert "pass_filenames: false" in manifest
    assert "language: python" in manifest


def test_staged_deletion_is_not_scanned_and_does_not_fail(repo, capsys):
    write_tree(repo, {"old.py": f"K = '{KEY}'\n", "keep.py": "x = 1\n"})
    commit_all(repo)
    git(repo, "rm", "-q", "old.py")
    code, report, _ = staged_scan(capsys, repo)
    assert code == 0
    assert report["summary"]["files_scanned"] == 0


def test_pure_rename_adds_no_lines(repo, capsys):
    write_tree(repo, {"old.py": f"K = '{KEY}'\nx = 1\n"})
    commit_all(repo)
    git(repo, "mv", "old.py", "new.py")
    code, _, _ = staged_scan(capsys, repo)
    assert code == 0


def test_secret_added_while_renaming_is_reported_under_the_new_name(repo, capsys):
    write_tree(repo, {"old.py": "x = 1\ny = 2\nz = 3\nw = 4\n"})
    commit_all(repo)
    git(repo, "mv", "old.py", "new.py")
    write_tree(repo, {"new.py": f"x = 1\ny = 2\nz = 3\nw = 4\nK = '{KEY}'\n"})
    git(repo, "add", "new.py")
    code, report, _ = staged_scan(capsys, repo)
    assert code == 1
    assert [(f["file"], f["line"]) for f in report["findings"]] == [("new.py", 5)]


def test_all_staged_files_are_scanned_together(repo, capsys):
    other = "AKIA" + fake.synthetic(16, "second", fake.UPPER_DIGITS)
    write_tree(
        repo,
        {"a.py": f"K = '{KEY}'\n", "b/c.py": f"K = '{other}'\n", "clean.py": "x = 1\n"},
    )
    git(repo, "add", "-A")
    _, report, _ = staged_scan(capsys, repo)
    assert sorted(f["file"] for f in report["findings"]) == ["a.py", "b/c.py"]
    assert report["summary"]["files_scanned"] == 3
