from pathlib import Path

from pysecscan.walker import walk


def test_skips_git_and_venv_dirs(tmp_path: Path):
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text("[core]\n")
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv" / "pyvenv.cfg").write_text("home = /usr\n")
    (tmp_path / "src.py").write_text("print('hi')\n")

    found = {p.name for p in walk(tmp_path)}
    assert found == {"src.py"}


def test_skips_binary_files(tmp_path: Path):
    (tmp_path / "a.txt").write_text("hello\n")
    (tmp_path / "b.bin").write_bytes(b"hello\x00world")

    found = {p.name for p in walk(tmp_path)}
    assert found == {"a.txt"}


def test_walks_single_file(tmp_path: Path):
    f = tmp_path / "lone.txt"
    f.write_text("data\n")
    assert list(walk(f)) == [f]


def test_respects_gitignore_for_files(tmp_path: Path):
    (tmp_path / ".gitignore").write_text("secret.txt\n")
    (tmp_path / "secret.txt").write_text("AKIAIOSFODNN7EXAMPLE\n")
    (tmp_path / "ok.txt").write_text("hi\n")

    found = {p.name for p in walk(tmp_path)}
    assert found == {".gitignore", "ok.txt"}


def test_respects_gitignore_for_directories(tmp_path: Path):
    (tmp_path / ".gitignore").write_text("artifacts/\n")
    (tmp_path / "artifacts").mkdir()
    (tmp_path / "artifacts" / "leak.txt").write_text("AKIAIOSFODNN7EXAMPLE\n")
    (tmp_path / "src.py").write_text("print('hi')\n")

    found = {p.name for p in walk(tmp_path)}
    assert "leak.txt" not in found
    assert "src.py" in found


def test_no_gitignore_disables_filtering(tmp_path: Path):
    (tmp_path / ".gitignore").write_text("secret.txt\n")
    (tmp_path / "secret.txt").write_text("hi\n")

    found = {p.name for p in walk(tmp_path, respect_gitignore=False)}
    assert "secret.txt" in found


def test_extra_excludes_apply(tmp_path: Path):
    (tmp_path / "keep.txt").write_text("hi\n")
    (tmp_path / "drop.log").write_text("hi\n")

    found = {p.name for p in walk(tmp_path, extra_excludes=["*.log"])}
    assert found == {"keep.txt"}
