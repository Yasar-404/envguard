import json
import re
import shutil

import pytest

import synthetic as fake
from envguard import git as envguard_git
from envguard.cli import main
from repo import commit_all, git, init_repo, write_tree

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")

KEY = fake.aws_access_key()


def scan_json(capsys, *args):
    code = main(["scan", *map(str, args), "--json"])
    out, err = capsys.readouterr()
    return code, json.loads(out) if out else None, err


@pytest.fixture
def repo(tmp_path):
    init_repo(tmp_path)
    return tmp_path


class TestWorkingTree:
    def test_gitignored_files_are_not_scanned(self, repo, capsys):
        write_tree(
            repo,
            {
                ".gitignore": "local.env\nbuild-output/\n",
                "local.env": f"KEY={KEY}\n",
                "build-output/out.txt": f"KEY={KEY}\n",
                "app.py": "print('hi')\n",
            },
        )
        code, report, _ = scan_json(capsys, repo)
        assert code == 0
        assert report["findings"] == []

    def test_nested_gitignore_is_honoured(self, repo, capsys):
        write_tree(repo, {"svc/.gitignore": "*.key\n", "svc/prod.key": f"K={KEY}\n"})
        code, _, _ = scan_json(capsys, repo)
        assert code == 0

    def test_untracked_files_are_scanned(self, repo, capsys):
        write_tree(repo, {"new.py": f"K = '{KEY}'\n"})
        code, report, _ = scan_json(capsys, repo)
        assert code == 1
        assert report["findings"][0]["file"] == "new.py"

    def test_tracked_file_matching_gitignore_is_still_scanned(self, repo, capsys):
        write_tree(repo, {".gitignore": "*.env\n", "prod.env": f"K={KEY}\n"})
        git(repo, "add", "-f", "prod.env", ".gitignore")
        commit_all(repo)
        code, report, _ = scan_json(capsys, repo)
        assert code == 1
        assert report["findings"][0]["file"] == "prod.env"

    def test_file_deleted_from_disk_but_still_tracked_does_not_break_the_scan(self, repo, capsys):
        write_tree(repo, {"gone.py": f"K = '{KEY}'\n", "keep.py": "x = 1\n"})
        commit_all(repo)
        (repo / "gone.py").unlink()
        code, report, _ = scan_json(capsys, repo)
        assert code == 0
        assert report["summary"]["files_skipped"] == 1

    def test_scanning_a_subdirectory_of_a_repo_is_scoped_to_it(self, repo, capsys):
        write_tree(repo, {"a/one.py": f"K = '{KEY}'\n", "b/two.py": f"K = '{KEY}'\n"})
        _, report, _ = scan_json(capsys, repo / "a")
        assert [f["file"] for f in report["findings"]] == ["one.py"]

    def test_git_dir_is_never_scanned(self, repo, capsys):
        write_tree(repo, {"a.py": f"K = '{KEY}'\n"})
        commit_all(repo)
        _, report, _ = scan_json(capsys, repo)
        assert all(not f["file"].startswith(".git/") for f in report["findings"])


class TestHistory:
    def test_finds_a_secret_that_was_removed(self, repo, capsys):
        write_tree(repo, {"config.py": f"import os\n\nAWS = '{KEY}'\nDEBUG = 1\n"})
        commit_all(repo, "add config")
        introducing = git(repo, "rev-parse", "HEAD").strip()
        write_tree(repo, {"config.py": "import os\n\nAWS = os.environ['AWS']\nDEBUG = 1\n"})
        commit_all(repo, "use env")

        code, report, _ = scan_json(capsys, repo)
        assert code == 0

        code, report, err = scan_json(capsys, repo, "--history")
        assert code == 1
        (finding,) = report["findings"]
        assert finding["rule_id"] == "aws-access-key"
        assert finding["file"] == "config.py"
        assert finding["line"] == 3
        assert finding["commit"] == introducing
        assert KEY not in json.dumps(report) + err

    def test_secret_still_in_working_tree_is_reported_once(self, repo, capsys):
        write_tree(repo, {"config.py": f"AWS = '{KEY}'\n"})
        commit_all(repo)
        write_tree(repo, {"README.md": "docs\n"})
        commit_all(repo)
        _, report, _ = scan_json(capsys, repo, "--history")
        assert len(report["findings"]) == 1
        assert report["findings"][0]["commit"] is None

    def test_secret_is_attributed_to_the_commit_that_introduced_it(self, repo, capsys):
        write_tree(repo, {"a.py": f"K = '{KEY}'\n"})
        commit_all(repo, "first")
        first = git(repo, "rev-parse", "HEAD").strip()
        write_tree(repo, {"a.py": f"# moved\nK = '{KEY}'\n"})
        commit_all(repo, "shift down a line")
        write_tree(repo, {"a.py": "gone = True\n"})
        commit_all(repo, "remove")

        _, report, _ = scan_json(capsys, repo, "--history")
        assert [f["commit"] for f in report["findings"]] == [first]

    def test_secrets_on_other_branches_are_found(self, repo, capsys):
        write_tree(repo, {"a.py": "x = 1\n"})
        commit_all(repo, "base")
        git(repo, "checkout", "-q", "-b", "feature")
        write_tree(repo, {"b.py": f"K = '{KEY}'\n"})
        commit_all(repo, "feature work")
        git(repo, "checkout", "-q", "-")
        code, report, _ = scan_json(capsys, repo, "--history")
        assert code == 1
        assert report["findings"][0]["file"] == "b.py"

    def test_max_commits_limits_how_far_back_history_is_read(self, repo, capsys):
        write_tree(repo, {"a.py": f"K = '{KEY}'\n"})
        commit_all(repo, "old")
        write_tree(repo, {"a.py": "x = 1\n"})
        commit_all(repo, "new")
        code, _, _ = scan_json(capsys, repo, "--history", "--max-commits", "1")
        assert code == 0
        code, _, _ = scan_json(capsys, repo, "--history", "--max-commits", "2")
        assert code == 1

    def test_history_respects_excludes_and_binary_extensions(self, repo, capsys):
        write_tree(
            repo,
            {"fixtures/a.py": f"K = '{KEY}'\n", "blob.png": f"K={KEY}\n", "node_modules/x.js": KEY},
        )
        commit_all(repo)
        write_tree(repo, {"fixtures/a.py": "x = 1\n"})
        commit_all(repo)
        code, _, _ = scan_json(capsys, repo, "--history", "--exclude", "fixtures/")
        assert code == 0

    def test_history_paths_are_relative_to_the_scanned_subdirectory(self, repo, capsys):
        write_tree(repo, {"svc/a.py": f"K = '{KEY}'\n", "other/b.py": f"K = '{KEY}'\n"})
        commit_all(repo)
        write_tree(repo, {"svc/a.py": "x = 1\n", "other/b.py": "x = 1\n"})
        commit_all(repo)
        _, report, _ = scan_json(capsys, repo / "svc", "--history")
        assert [f["file"] for f in report["findings"]] == ["a.py"]

    def test_file_names_with_spaces(self, repo, capsys):
        write_tree(repo, {"my config.py": f"K = '{KEY}'\n"})
        commit_all(repo)
        write_tree(repo, {"my config.py": "x = 1\n"})
        commit_all(repo)
        _, report, _ = scan_json(capsys, repo, "--history")
        assert report["findings"][0]["file"] == "my config.py"

    def test_empty_repository_has_no_history_findings(self, repo, capsys):
        code, report, _ = scan_json(capsys, repo, "--history")
        assert code == 0
        assert report["findings"] == []

    def test_history_of_a_single_file_is_rejected(self, repo, capsys):
        write_tree(repo, {"a.py": "x = 1\n"})
        commit_all(repo)
        code, _, err = scan_json(capsys, repo / "a.py", "--history")
        assert code == 2
        assert "directory" in err

    def test_text_output_shows_the_short_commit_and_no_secret(self, repo, capsys):
        write_tree(repo, {"a.py": f"K = '{KEY}'\n"})
        commit_all(repo)
        write_tree(repo, {"a.py": "x = 1\n"})
        commit_all(repo)
        main(["scan", str(repo), "--history"])
        out = capsys.readouterr().out
        assert re.search(r"a\.py:1 \(commit [0-9a-f]{8}\)", out)
        assert KEY not in out


class TestDiffParsing:
    def test_added_line_that_looks_like_a_file_header_is_not_mistaken_for_one(self, repo):
        write_tree(repo, {"real.txt": "++ b/decoy.txt\nsecond\n"})
        commit_all(repo)
        added = list(envguard_git.added_lines(repo))
        assert [(a.path, a.number, a.text) for a in added] == [
            ("real.txt", 1, "++ b/decoy.txt"),
            ("real.txt", 2, "second"),
        ]

    def test_hunk_line_numbers_track_insertions_in_the_middle_of_a_file(self, repo):
        write_tree(repo, {"a.txt": "one\ntwo\nthree\n"})
        commit_all(repo)
        write_tree(repo, {"a.txt": "one\ntwo\ninserted\nthree\nappended\n"})
        commit_all(repo)
        latest = [a for a in envguard_git.added_lines(repo, max_commits=1)]
        assert [(a.number, a.text) for a in latest] == [(3, "inserted"), (5, "appended")]

    def test_windows_line_endings_are_stripped(self, repo):
        write_tree(repo, {"a.txt": b"one\r\ntwo\r\n"})
        commit_all(repo)
        assert [a.text for a in envguard_git.added_lines(repo)] == ["one", "two"]

    def test_require_repository_rejects_plain_directories(self, tmp_path):
        with pytest.raises(envguard_git.GitError, match="not inside a git repository"):
            envguard_git.require_repository(tmp_path, "--history")
