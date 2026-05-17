import os
from pathlib import Path

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


def walk(root):
    root = Path(root)
    # accept a single file too, so `pysecscan scan some_file.py` works
    # without special-casing it in the CLI.
    if root.is_file():
        if not is_binary(root):
            yield root
        return

    for dirpath, dirnames, filenames in os.walk(root):
        # mutate dirnames in place so os.walk skips descending into these.
        # filtering after the fact would still walk all of node_modules.
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            p = Path(dirpath) / name
            try:
                if p.stat().st_size > MAX_BYTES:
                    continue
            except OSError:
                # broken symlink, permission denied, etc. just skip it.
                continue
            if is_binary(p):
                continue
            yield p
