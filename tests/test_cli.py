import json
import subprocess
import sys


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


def test_top_flag_limits_output(tmp_path):
    f = tmp_path / "test.zip"
    f.write_bytes(b"PK\x03\x04" + b"\x00" * 100)
    result = run([str(f), "--top", "1", "-q"])
    assert result.returncode == 0
    lines = [line for line in result.stdout.decode().splitlines() if "%" in line]
    assert len(lines) == 1


def test_min_confidence_filters_low_scores(tmp_path):
    f = tmp_path / "test.bmp"
    f.write_bytes(b"BM" + b"\x00" * 100)
    result = run([str(f), "--min-confidence", "30", "-q"])
    assert result.returncode == 1


def test_verbose_shows_hex_bytes(tmp_path):
    f = tmp_path / "test.png"
    f.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)
    result = run([str(f), "--verbose", "-q"])
    assert result.returncode == 0
    output = result.stdout.decode()
    assert "matched:" in output
    assert "89" in output
    assert "at offset 0" in output


def test_json_output_structure(tmp_path):
    f = tmp_path / "test.png"
    f.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)
    result = run([str(f), "--json"])
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert "file" in data
    assert "candidates" in data
    candidate = data["candidates"][0]
    assert candidate["name"] == "PNG image"
    assert candidate["confidence"] == 100
    assert "matched_bytes" in candidate
    assert "offset" in candidate


def test_list_flag_outputs_all_formats():
    result = run(["--list"])
    assert result.returncode == 0
    output = result.stdout.decode()
    assert "PNG image" in output
    assert "ELF executable" in output
    assert "ZIP archive" in output


def test_quiet_suppresses_banner(tmp_path):
    f = tmp_path / "test.png"
    f.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)
    result = run([str(f), "-q"])
    output = result.stdout.decode()
    assert "magicmatch" not in output.lower().replace("magicmatch", "", 0)
    assert "___" not in output
