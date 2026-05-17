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
