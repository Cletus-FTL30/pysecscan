import json
import subprocess
import sys
from pathlib import Path


def _run(args, cwd):
    return subprocess.run(
        [sys.executable, "-m", "pysecscan.cli", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
    )


def test_scan_text_format_reports_finding(tmp_path: Path):
    (tmp_path / "leak.txt").write_text("aws=AKIAIOSFODNN7EXAMPLE\n")
    result = _run(["scan", str(tmp_path)], cwd=tmp_path)
    assert result.returncode == 1
    assert "aws-access-key-id" in result.stdout
    assert "AKIAIOSFODNN7EXAMPLE" in result.stdout


def test_scan_json_format_emits_valid_json(tmp_path: Path):
    (tmp_path / "leak.txt").write_text("aws=AKIAIOSFODNN7EXAMPLE\n")
    result = _run(["scan", str(tmp_path), "--format", "json"], cwd=tmp_path)
    assert result.returncode == 1
    data = json.loads(result.stdout)
    assert len(data) == 1
    assert data[0]["rule"] == "aws-access-key-id"
    assert data[0]["line"] == 1


def test_scan_clean_exits_zero(tmp_path: Path):
    (tmp_path / "clean.txt").write_text("nothing to see here\n")
    result = _run(["scan", str(tmp_path)], cwd=tmp_path)
    assert result.returncode == 0


def test_scan_clean_json_is_empty_list(tmp_path: Path):
    (tmp_path / "clean.txt").write_text("nothing to see here\n")
    result = _run(["scan", str(tmp_path), "--format", "json"], cwd=tmp_path)
    assert result.returncode == 0
    assert json.loads(result.stdout) == []


def test_missing_path_exits_two(tmp_path: Path):
    result = _run(["scan", str(tmp_path / "nope")], cwd=tmp_path)
    assert result.returncode == 2


def test_scan_sarif_format_emits_valid_sarif(tmp_path: Path):
    (tmp_path / "leak.txt").write_text("aws=AKIAIOSFODNN7EXAMPLE\n")
    result = _run(["scan", str(tmp_path), "--format", "sarif"], cwd=tmp_path)
    assert result.returncode == 1
    doc = json.loads(result.stdout)
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "pysecscan"
    assert len(run["results"]) == 1
    res = run["results"][0]
    assert res["ruleId"] == "aws-access-key-id"
    loc = res["locations"][0]["physicalLocation"]
    # path should be relative to scan root
    assert loc["artifactLocation"]["uri"] == "leak.txt"
    assert loc["region"]["startLine"] == 1


def test_scan_sarif_clean_emits_empty_results(tmp_path: Path):
    (tmp_path / "clean.txt").write_text("nothing\n")
    result = _run(["scan", str(tmp_path), "--format", "sarif"], cwd=tmp_path)
    assert result.returncode == 0
    doc = json.loads(result.stdout)
    assert doc["runs"][0]["results"] == []
