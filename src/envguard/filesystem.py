from __future__ import annotations

import os
import re
import stat
from collections.abc import Iterable, Iterator
from pathlib import Path, PurePosixPath

from envguard import git

DEFAULT_EXCLUDES = (
    ".git/", "node_modules/", ".venv/", "venv/", "__pycache__/", "dist/", "build/",
    ".tox/", ".mypy_cache/", ".pytest_cache/", ".ruff_cache/", "vendor/",
    "*.min.js", "*.min.css", "*.map",
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "uv.lock",
    "Pipfile.lock", "Cargo.lock", "composer.lock", "go.sum",
)  # fmt: skip

BINARY_EXTENSIONS = frozenset(
    {
        ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".tiff", ".psd",
        ".pdf", ".zip", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".jar", ".war",
        ".woff", ".woff2", ".ttf", ".otf", ".eot",
        ".exe", ".dll", ".so", ".dylib", ".bin", ".o", ".a", ".class", ".pyc", ".pyd",
        ".mp3", ".mp4", ".mov", ".avi", ".wav", ".ogg", ".webm",
        ".sqlite", ".db", ".parquet", ".pickle", ".pkl",
    }
)  # fmt: skip

_BINARY_SNIFF_BYTES = 8192


class PathMatcher:
    """Gitignore-style path matching, shared by .gitignore, config and --exclude patterns.

    Supported: `*`, `?`, `**`, `[...]`, a leading `/` or an inner `/` to anchor a pattern,
    and a trailing `/` to match directories only. Negation (`!pattern`) is not supported.
    """

    def __init__(self, patterns: Iterable[str]) -> None:
        compiled = (_compile(pattern) for pattern in patterns)
        self._rules = [rule for rule in compiled if rule is not None]

    def excludes(self, path: str, is_dir: bool = False) -> bool:
        return any(regex.match(path) for regex, dir_only in self._rules if is_dir or not dir_only)

    def excludes_path(self, path: str) -> bool:
        """Like `excludes` for a file, but also true when a parent directory is excluded."""
        parts = path.split("/")
        parents = ("/".join(parts[:i]) for i in range(1, len(parts)))
        return any(self.excludes(parent, is_dir=True) for parent in parents) or self.excludes(path)


def _compile(pattern: str) -> tuple[re.Pattern[str], bool] | None:
    pattern = pattern.strip()
    if not pattern or pattern.startswith(("#", "!")):
        return None
    dir_only = pattern.endswith("/")
    pattern = pattern.rstrip("/")
    anchored = "/" in pattern
    body = _glob_to_regex(pattern.lstrip("/"))
    try:
        return re.compile(("^" if anchored else "(?:^|.*/)") + body + "$"), dir_only
    except re.error:
        return None


def _glob_to_regex(glob: str) -> str:
    out: list[str] = []
    i = 0
    while i < len(glob):
        char = glob[i]
        if glob.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
            continue
        if glob.startswith("**", i):
            out.append(".*")
            i += 2
            continue
        if char == "[" and (end := glob.find("]", i + 2)) != -1:
            members = glob[i + 1 : end]
            out.append("[" + ("^" + members[1:] if members.startswith("!") else members) + "]")
            i = end + 1
            continue
        out.append({"*": "[^/]*", "?": "[^/]"}.get(char) or re.escape(char))
        i += 1
    return "".join(out)


def exclude_patterns(user_patterns: Iterable[str]) -> tuple[str, ...]:
    return (*DEFAULT_EXCLUDES, *user_patterns)


def is_scannable_name(path: str) -> bool:
    return PurePosixPath(path).suffix.lower() not in BINARY_EXTENSIONS


def discover_files(root: Path, patterns: Iterable[str]) -> Iterator[str]:
    """Yield paths (relative to `root`, `/`-separated) worth reading, in a stable order."""
    patterns = tuple(patterns)
    tracked = git.list_files(root)
    if tracked is not None:
        matcher = PathMatcher(patterns)
        for path in tracked:
            if is_scannable_name(path) and not matcher.excludes_path(path):
                yield path
        return
    yield from _walk(root, PathMatcher([*patterns, *_read_gitignore(root)]))


def _read_gitignore(root: Path) -> list[str]:
    try:
        return (root / ".gitignore").read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []


def _walk(root: Path, matcher: PathMatcher) -> Iterator[str]:
    for directory, subdirs, filenames in os.walk(root):
        relative_dir = Path(directory).relative_to(root).as_posix()
        prefix = "" if relative_dir == "." else relative_dir + "/"
        subdirs[:] = sorted(d for d in subdirs if not matcher.excludes(prefix + d, is_dir=True))
        for name in sorted(filenames):
            path = prefix + name
            if is_scannable_name(path) and not matcher.excludes(path):
                yield path


def read_text(path: Path, max_size: int) -> str | None:
    """File contents, or None if it is a symlink, unreadable, too large or binary.

    The size is checked before reading, so oversized files are never loaded. Bytes that are
    not valid UTF-8 are replaced instead of failing the scan.
    """
    try:
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_size > max_size:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    if b"\0" in data[:_BINARY_SNIFF_BYTES]:
        return None
    return data.decode("utf-8", errors="replace")
