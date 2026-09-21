"""The hook exactly as a user gets it: installed from `.pre-commit-hooks.yaml` by pre-commit.

Each test builds a throwaway project whose `.pre-commit-config.yaml` points at a snapshot of
this checkout. pre-commit creates the hook's virtualenv once per test session and reuses it.
The tests need `git`, `pre-commit` and network access for the first environment build.
"""

import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

import synthetic as fake
from repo import commit_all, git, git_result, init_repo, write_tree

pytestmark = [
    pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed"),
    pytest.mark.skipif(
        importlib.util.find_spec("pre_commit") is None, reason="pre-commit is missing"
    ),
]

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SNAPSHOT_FILES = (".pre-commit-hooks.yaml", "pyproject.toml", "README.md", "LICENSE")
AWS_KEY = fake.aws_access_key()
GITHUB_TOKEN = fake.github_token()
SECRETS = (AWS_KEY, GITHUB_TOKEN)


@pytest.fixture(scope="session")
def pre_commit_home(tmp_path_factory):
    return tmp_path_factory.mktemp("pre-commit-home")


@pytest.fixture(scope="session")
def hook_repo(tmp_path_factory):
    """A Git repository holding the current sources, standing in for the published repository.

    It lives under the same temporary root as the projects that use it: pre-commit fails on
    Windows when a local hook repository is on a different drive from the project.
    """
    root = tmp_path_factory.mktemp("envguard-hook-repo")
    for name in SNAPSHOT_FILES:
        shutil.copy2(PROJECT_ROOT / name, root / name)
    ignore = shutil.ignore_patterns("__pycache__", "*.egg-info")
    shutil.copytree(PROJECT_ROOT / "src", root / "src", ignore=ignore)
    init_repo(root)
    commit_all(root, "snapshot")
    return root


@pytest.fixture
def hook_env(pre_commit_home):
    return {**os.environ, "PRE_COMMIT_HOME": str(pre_commit_home), "PRE_COMMIT_COLOR": "never"}


def pre_commit(project, env, *args):
    return subprocess.run(
        [sys.executable, "-m", "pre_commit", *args],
        cwd=project,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=600,
    )


def output(result):
    return result.stdout + result.stderr


def make_project(tmp_path, hook_repo, hook_args=()):
    """A repository configured with the EnvGuard hook, with the config file staged."""
    init_repo(tmp_path)
    rev = git(hook_repo, "rev-parse", "HEAD").strip()
    config = (
        "repos:\n"
        f'  - repo: "{hook_repo.as_posix()}"\n'
        f"    rev: {rev}\n"
        "    hooks:\n"
        "      - id: envguard\n"
    )
    if hook_args:
        config += f"        args: {json.dumps(list(hook_args))}\n"
    write_tree(tmp_path, {".pre-commit-config.yaml": config})
    git(tmp_path, "add", ".pre-commit-config.yaml")
    return tmp_path


@pytest.fixture
def project(tmp_path, hook_repo):
    return make_project(tmp_path, hook_repo)


def test_hook_fails_on_a_staged_secret_and_masks_it(project, hook_env):
    write_tree(project, {"config.py": f"import os\n\nAWS = '{AWS_KEY}'\n"})
    git(project, "add", "config.py")

    result = pre_commit(project, hook_env, "run", "envguard")

    assert result.returncode == 1
    assert "envguard" in output(result) and "Failed" in output(result)
    assert "AWS Access Key" in output(result)
    assert "config.py:3" in output(result)
    assert AWS_KEY not in output(result)


def test_hook_passes_on_clean_staged_content(project, hook_env):
    write_tree(project, {"main.py": "import os\n\nTOKEN = os.environ['TOKEN']\n"})
    git(project, "add", "main.py")

    result = pre_commit(project, hook_env, "run", "envguard")

    assert result.returncode == 0
    assert "Passed" in output(result)


def test_every_staged_file_is_inspected(project, hook_env):
    write_tree(
        project,
        {
            "clean.py": "x = 1\n",
            "first.py": f"K = '{AWS_KEY}'\n",
            "second/token.env": f"GITHUB_TOKEN={GITHUB_TOKEN}\n",
        },
    )
    git(project, "add", "-A")

    result = pre_commit(project, hook_env, "run", "envguard")

    assert result.returncode == 1
    assert "first.py:1" in output(result)
    assert "second/token.env:1" in output(result)
    assert "clean.py" not in output(result)
    assert not any(secret in output(result) for secret in SECRETS)


def test_secrets_that_are_not_staged_do_not_block(project, hook_env):
    write_tree(project, {"tracked.py": "x = 1\n"})
    git(project, "add", "tracked.py")
    commit_all(project, "base")
    write_tree(
        project,
        {
            "tracked.py": f"x = 1\nK = '{AWS_KEY}'\n",  # modified, not staged
            "untracked.env": f"GITHUB_TOKEN={GITHUB_TOKEN}\n",  # not added
            "staged.py": "y = 2\n",
        },
    )
    git(project, "add", "staged.py")

    result = pre_commit(project, hook_env, "run", "envguard")

    assert result.returncode == 0, output(result)


def test_files_and_all_files_do_not_widen_the_scan(project, hook_env):
    """The hook inspects only what is staged; pre-commit's file selection cannot change that."""
    write_tree(project, {"secret.env": f"AWS_ACCESS_KEY_ID={AWS_KEY}\n"})

    unstaged = pre_commit(project, hook_env, "run", "envguard", "--files", "secret.env")
    assert unstaged.returncode == 0

    git(project, "add", "secret.env")
    commit_all(project, "commit the secret without the hook installed")
    all_files = pre_commit(project, hook_env, "run", "envguard", "--all-files")
    assert all_files.returncode == 0


def test_hook_arguments_are_passed_to_envguard(tmp_path, hook_repo, hook_env):
    project = make_project(tmp_path, hook_repo, hook_args=["--exclude", "generated/"])
    write_tree(project, {"generated/keys.py": f"K = '{AWS_KEY}'\n"})
    git(project, "add", "generated/keys.py")

    assert pre_commit(project, hook_env, "run", "envguard").returncode == 0


def test_try_repo_exercises_the_staged_scan(project, hook_repo, hook_env):
    """`try-repo` runs the hook from the repository; it still only sees staged changes."""
    write_tree(project, {"test-secret.env": f"AWS_ACCESS_KEY_ID={AWS_KEY}\n"})
    git(project, "add", "test-secret.env")

    result = pre_commit(project, hook_env, "try-repo", str(hook_repo), "envguard")

    assert result.returncode == 1
    assert "AWS Access Key" in output(result)
    assert AWS_KEY not in output(result)


class TestInstalledHook:
    """`pre-commit install`, then plain `git commit`."""

    @pytest.fixture
    def installed(self, project, hook_env):
        installed = pre_commit(project, hook_env, "install")
        assert installed.returncode == 0, output(installed)
        return project

    def commit(self, project, hook_env):
        return git_result(project, "commit", "-m", "change", env=hook_env)

    def has_commits(self, project):
        return git_result(project, "rev-parse", "--verify", "HEAD").returncode == 0

    def test_a_commit_containing_a_secret_is_blocked(self, installed, hook_env):
        write_tree(installed, {"config.py": f"K = '{AWS_KEY}'\n"})
        git(installed, "add", "config.py")

        result = self.commit(installed, hook_env)

        assert result.returncode != 0
        assert "AWS Access Key" in output(result)
        assert AWS_KEY not in output(result)
        assert not self.has_commits(installed)

    def test_a_clean_commit_is_allowed(self, installed, hook_env):
        write_tree(installed, {"main.py": "print('hello')\n"})
        git(installed, "add", "main.py")

        result = self.commit(installed, hook_env)

        assert result.returncode == 0, output(result)
        assert self.has_commits(installed)

    def test_removing_the_secret_from_the_index_unblocks_the_commit(self, installed, hook_env):
        write_tree(installed, {"config.py": f"K = '{AWS_KEY}'\n"})
        git(installed, "add", "config.py")
        assert self.commit(installed, hook_env).returncode != 0

        write_tree(installed, {"config.py": "K = None\n"})
        git(installed, "add", "config.py")

        assert self.commit(installed, hook_env).returncode == 0
        assert self.has_commits(installed)

    def test_an_unstaged_secret_does_not_block_the_commit(self, installed, hook_env):
        write_tree(installed, {"main.py": "print('hello')\n", "later.env": f"K={AWS_KEY}\n"})
        git(installed, "add", "main.py")

        result = self.commit(installed, hook_env)

        assert result.returncode == 0, output(result)
        assert (installed / "later.env").read_text(encoding="utf-8") == f"K={AWS_KEY}\n"
