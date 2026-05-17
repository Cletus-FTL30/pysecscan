from pathlib import Path

from pysecscan.detectors import scan_text


def test_detects_aws_access_key():
    findings = list(scan_text(Path("x"), "key = AKIAIOSFODNN7EXAMPLE"))
    assert len(findings) == 1
    assert findings[0].rule == "aws-access-key-id"
    assert findings[0].match == "AKIAIOSFODNN7EXAMPLE"
    assert findings[0].line == 1


def test_detects_github_pat():
    text = "\ntoken: ghp_" + "a" * 36 + "\n"
    findings = list(scan_text(Path("x"), text))
    assert len(findings) == 1
    assert findings[0].rule == "github-pat"
    assert findings[0].line == 2


def test_ignores_plain_text():
    assert list(scan_text(Path("x"), "hello world, no secrets here")) == []


def test_reports_multiple_findings_with_correct_lines():
    text = "AKIAIOSFODNN7EXAMPLE\nplain\nghp_" + "b" * 36
    findings = list(scan_text(Path("x"), text))
    lines = sorted(f.line for f in findings)
    assert lines == [1, 3]


def test_detects_slack_bot_token():
    findings = list(scan_text(Path("x"), "token=xoxb-1234567890-abcdefghij"))
    assert len(findings) == 1
    assert findings[0].rule == "slack-token"


def test_detects_slack_webhook():
    url = "https://hooks.slack.com/services/T0ABC123/B0DEF456/aZ9bY8cX7wV6uT5sR4qP3oN2"
    findings = list(scan_text(Path("x"), f"hook = {url}"))
    assert len(findings) == 1
    assert findings[0].rule == "slack-webhook"


def test_detects_stripe_live_secret():
    findings = list(scan_text(Path("x"), "STRIPE=sk_live_" + "A" * 24))
    assert len(findings) == 1
    assert findings[0].rule == "stripe-live-secret"


def test_ignores_stripe_publishable():
    # pk_live_ is meant to be public; we shouldn't flag it.
    assert list(scan_text(Path("x"), "key = pk_live_" + "A" * 24)) == []


def test_detects_jwt():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    findings = list(scan_text(Path("x"), f"Authorization: Bearer {jwt}"))
    assert len(findings) == 1
    assert findings[0].rule == "jwt"
