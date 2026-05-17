import subprocess
from pathlib import Path


def is_git_repo(path):
    # `git -C <path> rev-parse --git-dir` returns 0 inside a repo (work tree
    # or bare) and non-zero otherwise. cheaper than parsing `git status`.
    result = subprocess.run(
        ["git", "-C", str(path), "rev-parse", "--git-dir"],
        capture_output=True,
        text=True,
    )
    return result.returncode == 0


def iter_blobs(repo):
    # rev-list --all --objects walks every object reachable from any ref.
    # output is one object per line. for blobs/trees it includes the path the
    # object was last seen at; for commits it's just the SHA.
    rev_list = subprocess.run(
        ["git", "-C", str(repo), "rev-list", "--all", "--objects"],
        capture_output=True,
        text=True,
        check=True,
    )

    # batch-check classifies each object without loading its contents, which
    # would be wasteful for trees/commits. %(rest) preserves the trailing
    # path field from rev-list so we don't have to re-parse.
    check = subprocess.run(
        [
            "git", "-C", str(repo),
            "cat-file", "--batch-check=%(objecttype) %(objectname) %(rest)",
        ],
        input=rev_list.stdout,
        capture_output=True,
        text=True,
        check=True,
    )

    # dedupe by SHA: the same blob can appear at many commits and many paths.
    # scanning it once per unique content is what matters for secret detection.
    seen = set()
    for line in check.stdout.splitlines():
        parts = line.split(" ", 2)
        if len(parts) < 3:
            continue
        objtype, sha, path = parts
        if objtype != "blob":
            continue
        if sha in seen:
            continue
        seen.add(sha)
        yield sha, path


def read_blob(repo, sha):
    # cat-file -p prints the raw decompressed object. bytes, not text:
    # historical blobs aren't guaranteed to be utf-8 (or text at all).
    result = subprocess.run(
        ["git", "-C", str(repo), "cat-file", "-p", sha],
        capture_output=True,
        check=True,
    )
    return result.stdout
