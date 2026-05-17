import re
from dataclasses import dataclass
from pathlib import Path

RULES = [
    ("aws-access-key-id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github-pat", re.compile(r"\bghp_[A-Za-z0-9]{36}\b")),
    ("github-fine-grained-pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{82}\b")),
]


@dataclass
class Finding:
    path: Path
    line: int
    rule: str
    match: str


def scan_text(path, text):
    for lineno, line in enumerate(text.splitlines(), 1):
        for rule, pattern in RULES:
            for m in pattern.finditer(line):
                yield Finding(path, lineno, rule, m.group(0))


def scan_file(path):
    try:
        text = Path(path).read_text(errors="replace")
    except OSError:
        return
    yield from scan_text(path, text)
