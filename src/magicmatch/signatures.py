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
    Signature(
        name="ISO 9660 disc image",
        mime_type="application/x-iso9660-image",
        magic=b"CD001",
        offset=32769,
        extensions=[".iso"],
    ),
    Signature(
        name="QCOW2 disk image",
        mime_type="application/x-qemu-disk",
        magic=b"QFI\xfb",
        extensions=[".qcow2"],
    ),
    Signature(
        name="VHDX disk image",
        mime_type="application/x-vhdx",
        magic=b"vhdxfile",
        extensions=[".vhdx"],
    ),
    Signature(
        name="SquashFS filesystem",
        mime_type="application/x-squashfs",
        magic=b"hsqs",
        extensions=[".sqsh"],
    ),
    Signature(
        name="ext2/3/4 filesystem",
        mime_type="application/x-ext4",
        magic=b"\x53\xef",
        offset=1080,
    ),
    Signature(
        name="NTFS filesystem",
        mime_type="application/x-ntfs",
        magic=b"NTFS    ",
        offset=3,
    ),
    Signature(
        name="PCAP capture (little-endian)",
        mime_type="application/vnd.tcpdump.pcap",
        magic=b"\xd4\xc3\xb2\xa1",
        extensions=[".pcap"],
    ),
    Signature(
        name="PCAP capture (big-endian)",
        mime_type="application/vnd.tcpdump.pcap",
        magic=b"\xa1\xb2\xc3\xd4",
        extensions=[".pcap"],
    ),
    Signature(
        name="PCAPNG capture",
        mime_type="application/x-pcapng",
        magic=b"\x0a\x0d\x0d\x0a",
        extensions=[".pcapng"],
    ),
    Signature(
        name="Windows Registry hive",
        mime_type="application/x-registry",
        magic=b"regf",
        extensions=["", ".dat"],
    ),
    Signature(
        name="Windows Event Log (v1)",
        mime_type="application/x-evt",
        magic=b"LfLe",
        extensions=[".evt"],
    ),
    Signature(
        name="Windows Event Log (v2)",
        mime_type="application/x-evtx",
        magic=b"ElfFile\x00",
        extensions=[".evtx"],
    ),
    Signature(
        name="Windows crash dump",
        mime_type="application/x-dmp",
        magic=b"MDMP",
        extensions=[".dmp"],
    ),
    Signature(
        name="Windows Prefetch",
        mime_type="application/x-prefetch",
        magic=b"SCCA",
        offset=4,
        extensions=[".pf"],
    ),
    Signature(
        name="Windows LNK shortcut",
        mime_type="application/x-ms-shortcut",
        magic=b"\x4c\x00\x00\x00\x01\x14\x02\x00",
        extensions=[".lnk"],
    ),
    Signature(
        name="PKCS#12 / PFX certificate",
        mime_type="application/x-pkcs12",
        magic=b"\x30\x82",
        extensions=[".pfx", ".p12"],
    ),
    Signature(
        name="Java KeyStore",
        mime_type="application/x-java-keystore",
        magic=b"\xfe\xed\xfe\xed",
        extensions=[".jks"],
    ),
    Signature(
        name="PGP message or key",
        mime_type="application/pgp",
        magic=b"-----BEGIN PGP ",
        extensions=[".asc", ".gpg"],
        mode="text",
    ),
    Signature(
        name="SSH private key (OpenSSH)",
        mime_type="application/x-ssh-key",
        magic=b"-----BEGIN OPENSSH PRIVATE KEY-----",
        mode="text",
    ),
    Signature(
        name="SQLite database",
        mime_type="application/x-sqlite3",
        magic=b"SQLite format 3\x00",
        extensions=[".db", ".sqlite"],
    ),
    Signature(
        name="MP3 audio",
        mime_type="audio/mpeg",
        magic=b"ID3",
        extensions=[".mp3"],
    ),
    Signature(
        name="MP4 video",
        mime_type="video/mp4",
        magic=b"ftyp",
        offset=4,
        extensions=[".mp4", ".m4a", ".m4v"],
    ),
    Signature(
        name="WAV audio",
        mime_type="audio/wav",
        magic=b"WAVE",
        offset=8,
        extensions=[".wav"],
    ),
    Signature(
        name="FLAC audio",
        mime_type="audio/flac",
        magic=b"fLaC",
        extensions=[".flac"],
    ),
    Signature(
        name="OGG container",
        mime_type="audio/ogg",
        magic=b"OggS",
        extensions=[".ogg", ".oga", ".ogv"],
    ),
    Signature(
        name="Matroska / WebM",
        mime_type="video/x-matroska",
        magic=b"\x1a\x45\xdf\xa3",
        extensions=[".mkv", ".webm"],
    ),
    Signature(
        name="AVI video",
        mime_type="video/x-msvideo",
        magic=b"AVI ",
        offset=8,
        extensions=[".avi"],
    ),
    Signature(
        name="SWF (Flash)",
        mime_type="application/x-shockwave-flash",
        magic=b"FWS",
        extensions=[".swf"],
    ),
    Signature(
        name="SWF (Flash, compressed)",
        mime_type="application/x-shockwave-flash",
        magic=b"CWS",
        extensions=[".swf"],
    ),
    Signature(
        name="Android Binary XML",
        mime_type="application/x-android-axml",
        magic=b"\x03\x00\x08\x00",
    ),
    Signature(
        name="Android Resource Table",
        mime_type="application/x-android-arsc",
        magic=b"\x02\x00\x0c\x00",
    ),
    Signature(
        name="U-Boot image",
        mime_type="application/x-uboot",
        magic=b"\x27\x05\x19\x56",
    ),
    Signature(
        name="UEFI firmware volume",
        mime_type="application/x-uefi",
        magic=b"_FVH",
        offset=40,
    ),
]
