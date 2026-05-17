from pathlib import Path

from pysecscan.detectors import scan_text
from pysecscan.entropy import shannon


def test_shannon_empty_is_zero():
    assert shannon("") == 0.0


def test_shannon_repeated_char_is_zero():
    assert shannon("aaaaaa") == 0.0


def test_shannon_random_base64_is_high():
    # a random 32-byte base64 token should clear our 4.5 default easily.
    sample = "kJ8nQp2vR7sT4uW9xY3zA1bC5dE6fG0h"
    assert shannon(sample) > 4.5


def test_entropy_detects_unknown_random_token():
    text = "API_TOKEN = kJ8nQp2vR7sT4uW9xY3zA1bC5dE6fG0h"
    findings = list(scan_text(Path("x"), text))
    rules = {f.rule for f in findings}
    assert "high-entropy-string" in rules


def test_entropy_ignores_plain_identifier():
    # a long but repetitive constant name shouldn't be flagged.
    text = "THIS_IS_A_LONG_CONSTANT_NAME_FOR_CONFIG = 1"
    findings = list(scan_text(Path("x"), text))
    assert all(f.rule != "high-entropy-string" for f in findings)


def test_entropy_disabled_skips_high_entropy_strings():
    text = "API_TOKEN = kJ8nQp2vR7sT4uW9xY3zA1bC5dE6fG0h"
    findings = list(scan_text(Path("x"), text, entropy_threshold=None))
    assert findings == []


def test_entropy_does_not_double_report_named_rule():
    # a JWT's third segment is long and high-entropy, so it would also match
    # the entropy candidate. dedup logic should suppress the generic finding
    # in favor of the named "jwt" rule.
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    findings = list(scan_text(Path("x"), f"token = {jwt}"))
    rules = [f.rule for f in findings]
    assert "jwt" in rules
    assert "high-entropy-string" not in rules
