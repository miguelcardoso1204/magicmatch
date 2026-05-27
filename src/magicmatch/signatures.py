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
]
