import re
from dataclasses import dataclass
from pathlib import Path

from pysecscan.entropy import shannon

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
    # slack tokens. prefixes: xoxb (bot), xoxp (user), xoxa (workspace),
    # xoxr (refresh), xoxs (session). length varies a lot across types so
    # we just require a reasonable minimum after the dash.
    ("slack-token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    # slack incoming webhook URL. leaking one of these lets anyone post into
    # the channel it was created for.
    ("slack-webhook", re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+")),
    # stripe live secret keys. only flagging live (sk_live, rk_live);
    # publishable keys (pk_*) are meant to be public, and test keys are
    # low-risk enough to skip until we have severity levels.
    ("stripe-live-secret", re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{24,}\b")),
    # JWT: three base64url segments joined by dots. header almost always
    # starts with eyJ (that's `{"` in base64), which cuts a lot of noise
    # vs. matching any three dot-separated tokens.
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")),
]

# generic candidate for the entropy pass: a longish run of base64-ish chars.
# 24 chars is short enough to catch a random 16-byte token (base64 = 24 chars),
# long enough to skip most identifiers and short hashes.
CANDIDATE = re.compile(r"[A-Za-z0-9+/=_\-]{24,}")
DEFAULT_ENTROPY = 4.5


@dataclass
class Finding:
    path: Path
    line: int
    rule: str
    match: str
    # set when scanning git history. carries the (short) blob SHA so reports
    # can distinguish "found in current tree" from "found in old commit".
    blob: str | None = None


def scan_text(path, text, entropy_threshold=DEFAULT_ENTROPY):
    # scan line-by-line so we can report a line number, and so the regex
    # engine never has to backtrack across a giant single string.
    for lineno, line in enumerate(text.splitlines(), 1):
        # track spans matched by named rules so the entropy pass doesn't
        # double-report the same string under a generic name.
        named_spans = []
        for rule, pattern in RULES:
            for m in pattern.finditer(line):
                yield Finding(path, lineno, rule, m.group(0))
                named_spans.append((m.start(), m.end()))

        if entropy_threshold is None:
            continue

        for m in CANDIDATE.finditer(line):
            if any(s <= m.start() < e or s < m.end() <= e for s, e in named_spans):
                continue
            token = m.group(0)
            if shannon(token) >= entropy_threshold:
                yield Finding(path, lineno, "high-entropy-string", token)


def scan_file(path, entropy_threshold=DEFAULT_ENTROPY):
    try:
        # errors="replace" so one weirdly-encoded byte doesn't make us drop
        # the whole file. we're looking for ascii-ish secret patterns anyway.
        text = Path(path).read_text(errors="replace")
    except OSError:
        return
    yield from scan_text(path, text, entropy_threshold=entropy_threshold)
