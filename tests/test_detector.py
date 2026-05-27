import pytest

from magicmatch.detector import Detector


def test_file_not_found(tmp_path):
    d = Detector()
    with pytest.raises(FileNotFoundError):
        d.identify(tmp_path / "nonexistent.bin")


def test_empty_file_returns_no_candidates(tmp_path):
    f = tmp_path / "empty.bin"
    f.write_bytes(b"")
    assert Detector().identify(f) == []


def test_unknown_bytes_returns_no_candidates(tmp_path):
    f = tmp_path / "random.bin"
    f.write_bytes(b"\x00\x01\x02\x03\x04\x05\x06\x07")
    assert Detector().identify(f) == []


def test_candidates_sorted_by_confidence_descending(tmp_path):
    from magicmatch.signatures import Signature

    sigs = [
        Signature(name="Short", mime_type="a/b", magic=b"\xAA\xBB"),
        Signature(name="Long", mime_type="c/d", magic=b"\xAA\xBB\xCC\xDD\xEE\xFF\x11\x22"),
    ]
    f = tmp_path / "test.bin"
    f.write_bytes(b"\xAA\xBB\xCC\xDD\xEE\xFF\x11\x22" + b"\x00" * 10)
    results = Detector(signatures=sigs).identify(f)
    assert results[0].name == "Long"
    assert results[1].name == "Short"
    assert results[0].confidence > results[1].confidence


def test_detects_png(tmp_path):
    f = tmp_path / "test.png"
    f.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)
    candidates = Detector().identify(f)
    assert len(candidates) >= 1
    top = candidates[0]
    assert top.name == "PNG image"
    assert top.mime_type == "image/png"
    assert top.confidence == 100
    assert top.extensions == [".png"]
    assert top.matched_bytes == b"\x89PNG\r\n\x1a\n"
    assert top.offset == 0
