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
]
