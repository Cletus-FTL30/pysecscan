import os
from pathlib import Path

import pathspec

# dirs we never want to walk into. .git holds packed objects (huge, binary),
# venvs and node_modules are vendored deps, the rest are build output or caches.
SKIP_DIRS = {".git", ".venv", "venv", "__pycache__", "node_modules", "dist", "build"}

# anything bigger than this is almost certainly not source code (lockfiles,
# generated assets, fixtures). regex scanning it just burns time.
MAX_BYTES = 5_000_000


def is_binary(path):
    # cheap heuristic: real text files almost never contain a null byte in the
    # first 8KB. avoids pulling in chardet or full mimetype detection.
    try:
        with open(path, "rb") as f:
            return b"\x00" in f.read(8192)
    except OSError:
        return True


def _load_gitignore(root):
    # only reading the top-level .gitignore for now. nested .gitignore files
    # are a real thing but handling them correctly (with the right precedence)
    # is a lot of code for the marginal coverage on most repos.
    gi = root / ".gitignore"
    if not gi.is_file():
        return None
    try:
        lines = gi.read_text(errors="replace").splitlines()
    except OSError:
        return None
    return pathspec.PathSpec.from_lines("gitignore", lines)


def walk(root, respect_gitignore=True, extra_excludes=None):
    root = Path(root)
    # accept a single file too, so `pysecscan scan some_file.py` works
    # without special-casing it in the CLI.
    if root.is_file():
        if not is_binary(root):
            yield root
        return

    spec = _load_gitignore(root) if respect_gitignore else None
    # user-provided excludes use the same gitignore syntax so the mental
    # model is "extra lines you could have put in .gitignore".
    extras = (
        pathspec.PathSpec.from_lines("gitignore", extra_excludes)
        if extra_excludes
        else None
    )

    def _ignored(rel, is_dir):
        # gitignore treats directories specially: a pattern like "build/"
        # only matches when we tell it the path is a directory (trailing /).
        candidate = rel + "/" if is_dir else rel
        if spec and spec.match_file(candidate):
            return True
        if extras and extras.match_file(candidate):
            return True
        return False

    for dirpath, dirnames, filenames in os.walk(root):
        # mutate dirnames in place so os.walk skips descending into these.
        # filtering after the fact would still walk all of node_modules.
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        if spec or extras:
            kept = []
            for d in dirnames:
                rel = str((Path(dirpath) / d).relative_to(root))
                if not _ignored(rel, is_dir=True):
                    kept.append(d)
            dirnames[:] = kept

        for name in filenames:
            p = Path(dirpath) / name
            if spec or extras:
                rel = str(p.relative_to(root))
                if _ignored(rel, is_dir=False):
                    continue
            try:
                if p.stat().st_size > MAX_BYTES:
                    continue
            except OSError:
                # broken symlink, permission denied, etc. just skip it.
                continue
            if is_binary(p):
                continue
            yield p
