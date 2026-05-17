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
