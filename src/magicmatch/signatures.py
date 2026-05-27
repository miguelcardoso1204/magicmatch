from dataclasses import dataclass, field


@dataclass
class Signature:
    name: str
    mime_type: str
    magic: bytes
    offset: int = 0
    extensions: list[str] = field(default_factory=list)
    mode: str = "binary"


@dataclass
class Candidate:
    confidence: int
    name: str
    mime_type: str
    extensions: list[str]
    matched_bytes: bytes
    offset: int


SIGNATURES: list[Signature] = [
    Signature(
        name="PNG image",
        mime_type="image/png",
        magic=b"\x89PNG\r\n\x1a\n",
        offset=0,
        extensions=[".png"],
    ),
    Signature(
        name="JPEG image",
        mime_type="image/jpeg",
        magic=b"\xff\xd8\xff",
        extensions=[".jpg", ".jpeg"],
    ),
    Signature(
        name="GIF image",
        mime_type="image/gif",
        magic=b"GIF87a",
        extensions=[".gif"],
    ),
    Signature(
        name="GIF image",
        mime_type="image/gif",
        magic=b"GIF89a",
        extensions=[".gif"],
    ),
    Signature(
        name="BMP image",
        mime_type="image/bmp",
        magic=b"BM",
        extensions=[".bmp"],
    ),
    Signature(
        name="WebP image",
        mime_type="image/webp",
        magic=b"WEBP",
        offset=8,
        extensions=[".webp"],
    ),
    Signature(
        name="TIFF image (little-endian)",
        mime_type="image/tiff",
        magic=b"II*\x00",
        extensions=[".tiff", ".tif"],
    ),
    Signature(
        name="TIFF image (big-endian)",
        mime_type="image/tiff",
        magic=b"MM\x00*",
        extensions=[".tiff", ".tif"],
    ),
    Signature(
        name="ICO icon",
        mime_type="image/x-icon",
        magic=b"\x00\x00\x01\x00",
        extensions=[".ico"],
    ),
    Signature(
        name="PDF document",
        mime_type="application/pdf",
        magic=b"%PDF",
        extensions=[".pdf"],
    ),
    Signature(
        name="ZIP archive",
        mime_type="application/zip",
        magic=b"PK\x03\x04",
        extensions=[".zip"],
    ),
    Signature(
        name="Java Archive",
        mime_type="application/java-archive",
        magic=b"PK\x03\x04",
        extensions=[".jar"],
    ),
    Signature(
        name="Office Open XML",
        mime_type="application/vnd.openxmlformats",
        magic=b"PK\x03\x04",
        extensions=[".docx", ".xlsx", ".pptx"],
    ),
    Signature(
        name="Android APK",
        mime_type="application/vnd.android.package-archive",
        magic=b"PK\x03\x04",
        extensions=[".apk"],
    ),
    Signature(
        name="OLE2 compound document",
        mime_type="application/vnd.ms-office",
        magic=b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
        extensions=[".doc", ".xls", ".ppt", ".msi"],
    ),
    Signature(
        name="RTF document",
        mime_type="application/rtf",
        magic=b"{\\rtf",
        extensions=[".rtf"],
    ),
    Signature(
        name="CHM help file",
        mime_type="application/vnd.ms-htmlhelp",
        magic=b"ITSF",
        extensions=[".chm"],
    ),
    Signature(
        name="ELF executable",
        mime_type="application/x-elf",
        magic=b"\x7fELF",
        extensions=[".elf", ".so", ""],
    ),
    Signature(
        name="PE executable",
        mime_type="application/vnd.microsoft.portable-executable",
        magic=b"MZ",
        extensions=[".exe", ".dll", ".sys"],
    ),
    Signature(
        name="Mach-O 32-bit (little-endian)",
        mime_type="application/x-mach-binary",
        magic=b"\xce\xfa\xed\xfe",
    ),
    Signature(
        name="Mach-O 64-bit (little-endian)",
        mime_type="application/x-mach-binary",
        magic=b"\xcf\xfa\xed\xfe",
    ),
    Signature(
        name="Mach-O fat binary",
        mime_type="application/x-mach-binary",
        magic=b"\xca\xfe\xba\xbe",
    ),
    Signature(
        name="Java class file",
        mime_type="application/java-vm",
        magic=b"\xca\xfe\xba\xbe",
        extensions=[".class"],
    ),
    Signature(
        name="Dalvik Executable",
        mime_type="application/vnd.android.dex",
        magic=b"dex\n",
        extensions=[".dex"],
    ),
    Signature(
        name="AutoIt3 compiled script",
        mime_type="application/x-autoit",
        magic=b"AU3!",
        extensions=[".exe"],
    ),
    Signature(
        name="GZIP archive",
        mime_type="application/gzip",
        magic=b"\x1f\x8b",
        extensions=[".gz", ".tgz"],
    ),
    Signature(
        name="BZIP2 archive",
        mime_type="application/x-bzip2",
        magic=b"BZh",
        extensions=[".bz2"],
    ),
    Signature(
        name="XZ archive",
        mime_type="application/x-xz",
        magic=b"\xfd7zXZ\x00",
        extensions=[".xz"],
    ),
    Signature(
        name="7-Zip archive",
        mime_type="application/x-7z-compressed",
        magic=b"7z\xbc\xaf\x27\x1c",
        extensions=[".7z"],
    ),
    Signature(
        name="RAR archive (v4)",
        mime_type="application/vnd.rar",
        magic=b"Rar!\x1a\x07\x00",
        extensions=[".rar"],
    ),
    Signature(
        name="RAR archive (v5)",
        mime_type="application/vnd.rar",
        magic=b"Rar!\x1a\x07\x01\x00",
        extensions=[".rar"],
    ),
    Signature(
        name="Zstandard archive",
        mime_type="application/zstd",
        magic=b"\x28\xb5\x2f\xfd",
        extensions=[".zst"],
    ),
    Signature(
        name="LZ4 archive",
        mime_type="application/x-lz4",
        magic=b"\x04\x22\x4d\x18",
        extensions=[".lz4"],
    ),
    Signature(
        name="TAR archive",
        mime_type="application/x-tar",
        magic=b"ustar",
        offset=257,
        extensions=[".tar"],
    ),
    Signature(
        name="CAB archive",
        mime_type="application/vnd.ms-cab-compressed",
        magic=b"MSCF",
        extensions=[".cab"],
    ),
    Signature(
        name="CPIO archive",
        mime_type="application/x-cpio",
        magic=b"070701",
        extensions=[".cpio"],
    ),
]
