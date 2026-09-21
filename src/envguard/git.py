"""Thin wrappers around the git executable.

Everything runs as an argument list without a shell. Output is read as bytes and decoded
leniently, since file names and diffs are not guaranteed to be valid UTF-8.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from collections.abc import Iterator
from pathlib import Path
from typing import NamedTuple

from envguard.models import EnvGuardError

_GIT_TIMEOUT = 60
_COMMIT_MARKER = "\0"
_HUNK_HEADER = re.compile(r"@@ -\d+(?:,\d+)? \+(\d+)")


class GitError(EnvGuardError):
    pass


class AddedLine(NamedTuple):
    commit: str
    path: str
    number: int
    text: str


def _git(root: Path, *args: str) -> subprocess.CompletedProcess[bytes] | None:
    try:
        return subprocess.run(
            ["git", "-C", str(root), *args],
            capture_output=True,
            timeout=_GIT_TIMEOUT,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None


def list_files(root: Path) -> list[str] | None:
    """Tracked and untracked-but-not-ignored files under `root`, or None outside a repository.

    Asking git means nested `.gitignore` files, `info/exclude` and the user's global ignore
    file are all honoured without reimplementing them here.
    """
    proc = _git(root, "ls-files", "-z", "--cached", "--others", "--exclude-standard")
    if proc is None or proc.returncode != 0:
        return None
    names = {os.fsdecode(name) for name in proc.stdout.split(b"\0") if name}
    # Untracked nested repositories are listed as directories.
    return sorted(name for name in names if not name.endswith("/"))


def require_repository(root: Path) -> None:
    if shutil.which("git") is None:
        raise GitError("git executable not found; --history requires git")
    proc = _git(root, "rev-parse", "--is-inside-work-tree")
    if proc is None or proc.returncode != 0:
        raise GitError(f"{root} is not inside a git repository; --history requires one")


def added_lines(root: Path, max_commits: int | None = None) -> Iterator[AddedLine]:
    """Stream every line added in the history reachable from any ref, newest commit first.

    A single `git log -p -U0` process is used; only added lines are parsed, so unchanged
    content is never re-scanned. Paths are relative to `root`.
    """
    command = [
        "git", "-C", str(root), "-c", "core.quotepath=off",
        "log", "--all", "-p", "-U0", "--no-color", "--no-ext-diff", "--no-textconv",
        "--relative", "--format=%x00%H",
    ]  # fmt: skip
    if max_commits is not None:
        command.append(f"--max-count={max_commits}")

    commit = ""
    path: str | None = None
    number = 0
    in_header = False
    with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as proc:
        assert proc.stdout is not None
        for raw in proc.stdout:
            line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
            if line.startswith(_COMMIT_MARKER):
                commit, path, in_header = line[1:], None, False
            elif line.startswith("diff --git "):
                path, in_header = None, True
            elif in_header:
                if line.startswith("+++ "):
                    target = line[4:].rstrip("\t")
                    path = target[2:] if target.startswith("b/") else None
                elif line.startswith("@@"):
                    in_header = False
                    number = _first_added_line(line)
            elif line.startswith("@@"):
                number = _first_added_line(line)
            elif line.startswith("+") and path is not None:
                yield AddedLine(commit, path, number, line[1:])
                number += 1
    if proc.returncode != 0:
        raise GitError(f"git log failed with exit code {proc.returncode}")


def _first_added_line(hunk_header: str) -> int:
    match = _HUNK_HEADER.match(hunk_header)
    return int(match.group(1)) if match else 0
