import os

import pytest

from envguard.filesystem import (
    DEFAULT_EXCLUDES,
    PathMatcher,
    discover_files,
    exclude_patterns,
    is_scannable_name,
    read_text,
)
from repo import write_tree


class TestPathMatcher:
    @pytest.mark.parametrize(
        ("pattern", "path", "expected"),
        [
            ("*.log", "app.log", True),
            ("*.log", "logs/app.log", True),
            ("*.log", "app.log.txt", False),
            ("/build", "build", True),
            ("/build", "src/build", False),
            ("src/*.py", "src/a.py", True),
            ("src/*.py", "src/deep/a.py", False),
            ("docs/**", "docs/a/b.md", True),
            ("**/fixtures", "a/b/fixtures", True),
            ("a/**/z", "a/z", True),
            ("a/**/z", "a/b/c/z", True),
            ("file?.txt", "file1.txt", True),
            ("file?.txt", "file10.txt", False),
            ("[ab].txt", "a.txt", True),
            ("[!ab].txt", "a.txt", False),
            ("#comment", "#comment", False),
            ("!keep.txt", "keep.txt", False),
            ("", "anything", False),
        ],
    )
    def test_file_patterns(self, pattern, path, expected):
        assert PathMatcher([pattern]).excludes(path) is expected

    def test_directory_only_patterns_ignore_files(self):
        matcher = PathMatcher(["cache/"])
        assert matcher.excludes("cache", is_dir=True)
        assert not matcher.excludes("cache")

    def test_excluded_parent_directory_excludes_files_beneath(self):
        matcher = PathMatcher(["node_modules/"])
        assert matcher.excludes_path("web/node_modules/pkg/index.js")
        assert not matcher.excludes_path("web/src/index.js")

    def test_invalid_glob_is_ignored_rather_than_crashing(self):
        assert not PathMatcher(["[z-a]"]).excludes("a")


def test_default_excludes_cover_dependency_and_lock_files():
    matcher = PathMatcher(DEFAULT_EXCLUDES)
    assert matcher.excludes_path("node_modules/x/index.js")
    assert matcher.excludes_path("frontend/package-lock.json")
    assert matcher.excludes_path("static/app.min.js")
    assert not matcher.excludes_path("src/app.js")


def test_binary_extensions_are_not_scannable():
    assert not is_scannable_name("assets/logo.PNG")
    assert is_scannable_name("src/settings.py")
    assert is_scannable_name(".env")


class TestDiscoverWithoutGit:
    def test_honours_gitignore_and_excludes(self, tmp_path):
        write_tree(
            tmp_path,
            {
                ".gitignore": "secrets.env\nlocal/\n*.tmp\n",
                "app.py": "x",
                "secrets.env": "x",
                "local/notes.txt": "x",
                "src/cache.tmp": "x",
                "src/lib.py": "x",
                "node_modules/dep/index.js": "x",
                "docs/guide.md": "x",
            },
        )
        found = list(discover_files(tmp_path, exclude_patterns(["docs/"])))
        assert found == [".gitignore", "app.py", "src/lib.py"]

    def test_output_is_sorted_and_posix_style(self, tmp_path):
        write_tree(tmp_path, {"b/z.py": "x", "a.py": "x", "b/a.py": "x"})
        assert list(discover_files(tmp_path, ())) == ["a.py", "b/a.py", "b/z.py"]

    @pytest.mark.skipif(os.name == "nt", reason="symlinks need elevated rights on Windows")
    def test_symlinks_are_not_followed(self, tmp_path):
        outside = tmp_path / "outside"
        write_tree(outside, {"secret.txt": "x"})
        project = tmp_path / "project"
        write_tree(project, {"real.txt": "x"})
        (project / "link").symlink_to(outside)
        (project / "file_link.txt").symlink_to(outside / "secret.txt")
        assert list(discover_files(project, ())) == ["file_link.txt", "real.txt"]
        assert read_text(project / "file_link.txt", 1024) is None


class TestReadText:
    def test_reads_utf8(self, tmp_path):
        write_tree(tmp_path, {"a.txt": "héllo"})
        assert read_text(tmp_path / "a.txt", 1024) == "héllo"

    def test_replaces_invalid_bytes(self, tmp_path):
        write_tree(tmp_path, {"a.txt": b"ok \xff\xfe ok"})
        assert read_text(tmp_path / "a.txt", 1024) == "ok �� ok"

    def test_rejects_binary_content(self, tmp_path):
        write_tree(tmp_path, {"a.txt": b"text\x00more"})
        assert read_text(tmp_path / "a.txt", 1024) is None

    def test_rejects_files_over_the_limit(self, tmp_path):
        write_tree(tmp_path, {"a.txt": "x" * 100})
        assert read_text(tmp_path / "a.txt", 99) is None
        assert read_text(tmp_path / "a.txt", 100) == "x" * 100

    def test_missing_file_is_skipped(self, tmp_path):
        assert read_text(tmp_path / "nope.txt", 1024) is None
