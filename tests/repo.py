"""Helpers for building throwaway projects and git repositories in tests."""

from __future__ import annotations

import subprocess
from pathlib import Path


def write_tree(root: Path, files: dict[str, str | bytes]) -> None:
    for name, content in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8", newline="\n")


def git(root: Path, *args: str) -> str:
    result = subprocess.run(
        [
            "git", "-C", str(root),
            "-c", "user.name=EnvGuard Tests", "-c", "user.email=tests@envguard.invalid",
            "-c", "commit.gpgsign=false", "-c", "core.autocrlf=false",
            *args,
        ],
        capture_output=True,
        text=True,
        check=True,
    )  # fmt: skip
    return result.stdout


def init_repo(root: Path) -> None:
    git(root, "init", "-q")


def commit_all(root: Path, message: str = "commit") -> None:
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", message)
