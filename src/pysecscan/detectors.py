import re
from dataclasses import dataclass
from pathlib import Path

# patterns are anchored with \b so we don't match inside longer identifiers.
# starting with the highest-confidence rules (known prefixes, fixed lengths),
# which have near-zero false positives. entropy-based generic detection
# comes later as a separate layer.
RULES = [
    # AKIA = long-lived IAM access key, ASIA = temp STS creds. both are
    # 20 chars total: 4-char prefix plus 16 base32-ish chars.
    ("aws-access-key-id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    # classic GitHub personal access token: ghp_ plus 36 alphanumeric.
    ("github-pat", re.compile(r"\bghp_[A-Za-z0-9]{36}\b")),
    # fine-grained PAT (newer format): github_pat_ plus 82 chars incl. underscores.
    ("github-fine-grained-pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{82}\b")),
]


@dataclass
class Finding:
    path: Path
    line: int
    rule: str
    match: str


def scan_text(path, text):
    # scan line-by-line so we can report a line number, and so the regex
    # engine never has to backtrack across a giant single string.
    for lineno, line in enumerate(text.splitlines(), 1):
        for rule, pattern in RULES:
            for m in pattern.finditer(line):
                yield Finding(path, lineno, rule, m.group(0))


def scan_file(path):
    try:
        # errors="replace" so one weirdly-encoded byte doesn't make us drop
        # the whole file. we're looking for ascii-ish secret patterns anyway.
        text = Path(path).read_text(errors="replace")
    except OSError:
        return
    yield from scan_text(path, text)
