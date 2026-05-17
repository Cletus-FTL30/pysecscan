import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from pysecscan.history import is_git_repo, iter_blobs, read_blob


def _git(repo, *args):
    # isolated env so the test never picks up the user's git config.
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "Test",
        "GIT_AUTHOR_EMAIL": "test@test.test",
        "GIT_COMMITTER_NAME": "Test",
        "GIT_COMMITTER_EMAIL": "test@test.test",
    }
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
        env=env,
    )


@pytest.fixture
def repo(tmp_path):
    _git(tmp_path, "init", "-q", "-b", "main")
    return tmp_path


def test_is_git_repo_true_for_init(repo):
    assert is_git_repo(repo) is True


def test_is_git_repo_false_for_plain_dir(tmp_path):
    assert is_git_repo(tmp_path) is False


def test_iter_blobs_finds_deleted_file_content(repo):
    # the whole point of history scanning: a secret was committed, then
    # later deleted. the working tree is clean but the blob is still in
    # the object database, and that's what attackers grep for.
    (repo / "leak.txt").write_text("AKIAIOSFODNN7EXAMPLE\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "leak")
    (repo / "leak.txt").unlink()
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "remove leak")

    blobs = list(iter_blobs(repo))
    paths = [path for _, path in blobs]
    assert "leak.txt" in paths

    sha = next(s for s, p in blobs if p == "leak.txt")
    content = read_blob(repo, sha).decode()
    assert "AKIAIOSFODNN7EXAMPLE" in content


def test_history_cli_reports_finding(repo):
    (repo / "leak.txt").write_text("aws=AKIAIOSFODNN7EXAMPLE\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "leak")
    (repo / "leak.txt").unlink()
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "remove")

    result = subprocess.run(
        [sys.executable, "-m", "pysecscan.cli", "history", str(repo), "--format", "json"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    data = json.loads(result.stdout)
    assert any(h["rule"] == "aws-access-key-id" for h in data)
    # blob SHA should be populated for history findings
    assert all(h["blob"] is not None for h in data if h["rule"] == "aws-access-key-id")


def test_history_cli_refuses_non_repo(tmp_path):
    result = subprocess.run(
        [sys.executable, "-m", "pysecscan.cli", "history", str(tmp_path)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 2
    assert "not a git repo" in result.stderr
