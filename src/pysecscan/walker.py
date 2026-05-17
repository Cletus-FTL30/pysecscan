import os
from pathlib import Path

SKIP_DIRS = {".git", ".venv", "venv", "__pycache__", "node_modules", "dist", "build"}
MAX_BYTES = 5_000_000


def is_binary(path):
    try:
        with open(path, "rb") as f:
            return b"\x00" in f.read(8192)
    except OSError:
        return True


def walk(root):
    root = Path(root)
    if root.is_file():
        if not is_binary(root):
            yield root
        return

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            p = Path(dirpath) / name
            try:
                if p.stat().st_size > MAX_BYTES:
                    continue
            except OSError:
                continue
            if is_binary(p):
                continue
            yield p
