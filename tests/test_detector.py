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


@pytest.mark.parametrize(
    "raw_bytes, expected_name, expected_mime",
    [
        (b"\xff\xd8\xff" + b"\x00" * 10, "JPEG image", "image/jpeg"),
        (b"GIF87a" + b"\x00" * 10, "GIF image", "image/gif"),
        (b"GIF89a" + b"\x00" * 10, "GIF image", "image/gif"),
        (b"BM" + b"\x00" * 10, "BMP image", "image/bmp"),
        (b"RIFF\x12\x34\x56\x78WEBP" + b"\x00" * 10, "WebP image", "image/webp"),
        (b"II*\x00" + b"\x00" * 10, "TIFF image (little-endian)", "image/tiff"),
        (b"MM\x00*" + b"\x00" * 10, "TIFF image (big-endian)", "image/tiff"),
        (b"\x00\x00\x01\x00" + b"\x00" * 10, "ICO icon", "image/x-icon"),
    ],
)
def test_detects_image_format(tmp_path, raw_bytes, expected_name, expected_mime):
    f = tmp_path / "test"
    f.write_bytes(raw_bytes)
    candidates = Detector().identify(f)
    names = [c.name for c in candidates]
    assert expected_name in names, f"Expected {expected_name!r}, got {names}"
    match = next(c for c in candidates if c.name == expected_name)
    assert match.mime_type == expected_mime


@pytest.mark.parametrize(
    "raw_bytes, expected_name, expected_mime",
    [
        (b"%PDF-1.4\n" + b"\x00" * 10, "PDF document", "application/pdf"),
        (b"PK\x03\x04" + b"\x00" * 10, "ZIP archive", "application/zip"),
        (b"PK\x03\x04" + b"\x00" * 10, "Java Archive", "application/java-archive"),
        (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 10, "OLE2 compound document",
         "application/vnd.ms-office"),
        (b"{\\rtf1" + b"\x00" * 10, "RTF document", "application/rtf"),
        (b"ITSF" + b"\x00" * 10, "CHM help file", "application/vnd.ms-htmlhelp"),
    ],
)
def test_detects_document_format(tmp_path, raw_bytes, expected_name, expected_mime):
    f = tmp_path / "test"
    f.write_bytes(raw_bytes)
    candidates = Detector().identify(f)
    names = [c.name for c in candidates]
    assert expected_name in names, f"Expected {expected_name!r}, got {names}"


@pytest.mark.parametrize(
    "raw_bytes, expected_name, expected_mime",
    [
        (b"\x7fELF" + b"\x00" * 10, "ELF executable", "application/x-elf"),
        (b"MZ" + b"\x00" * 10, "PE executable",
         "application/vnd.microsoft.portable-executable"),
        (b"\xce\xfa\xed\xfe" + b"\x00" * 10, "Mach-O 32-bit (little-endian)",
         "application/x-mach-binary"),
        (b"\xcf\xfa\xed\xfe" + b"\x00" * 10, "Mach-O 64-bit (little-endian)",
         "application/x-mach-binary"),
        (b"\xca\xfe\xba\xbe" + b"\x00" * 10, "Mach-O fat binary",
         "application/x-mach-binary"),
        (b"\xca\xfe\xba\xbe" + b"\x00" * 10, "Java class file",
         "application/java-vm"),
        (b"dex\n035\x00" + b"\x00" * 10, "Dalvik Executable",
         "application/vnd.android.dex"),
        (b"AU3!" + b"\x00" * 10, "AutoIt3 compiled script",
         "application/x-autoit"),
    ],
)
def test_detects_executable_format(tmp_path, raw_bytes, expected_name, expected_mime):
    f = tmp_path / "test"
    f.write_bytes(raw_bytes)
    candidates = Detector().identify(f)
    names = [c.name for c in candidates]
    assert expected_name in names, f"Expected {expected_name!r}, got {names}"
