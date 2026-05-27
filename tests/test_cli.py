import json
import subprocess
import sys

import pytest


def run(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "magicmatch.cli"] + args,
        capture_output=True,
    )


def test_identifies_png(tmp_path):
    f = tmp_path / "test.png"
    f.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)
    result = run([str(f), "-q"])
    assert result.returncode == 0
    assert "PNG image" in result.stdout.decode()
    assert "image/png" in result.stdout.decode()
    assert "100%" in result.stdout.decode()


def test_unknown_file_exits_1(tmp_path):
    f = tmp_path / "unknown.bin"
    f.write_bytes(b"\x00\x01\x02\x03")
    result = run([str(f), "-q"])
    assert result.returncode == 1
    assert "Unknown" in result.stdout.decode()


def test_missing_file_exits_2():
    result = run(["/nonexistent/path/file.bin"])
    assert result.returncode == 2
