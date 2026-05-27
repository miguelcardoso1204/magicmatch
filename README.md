# magicmatch

A Python CLI tool that identifies file types by inspecting their magic bytes — sequences of bytes at known offsets within a file that act as a reliable fingerprint, independent of file extension.

Built from scratch with no external dependencies (no `python-magic` / `libmagic`).

## Installation

```bash
git clone https://github.com/miguelcardoso1204/magicmatch.git
cd magicmatch
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Usage

```bash
magicmatch photo.png               # identify a file
magicmatch photo.png -q            # quiet mode (no banner)
magicmatch photo.png --verbose     # show matched bytes in hex
magicmatch photo.png --json        # machine-readable JSON output
magicmatch --list                  # list all supported formats
magicmatch file.bin --top 5        # show top 5 candidates
magicmatch file.bin --min-confidence 50  # only show candidates >= 50%
```

Exit codes: `0` match found, `1` unknown file type, `2` error.

## How confidence works

When a file's bytes match a signature, the confidence score reflects how specific that match is. The formula is grounded in keyspace math:

```
confidence = min(100, len(magic_bytes) * 100 // 8)
```

Each byte of magic has 256 possible values. At 8 bytes, the keyspace is 256^8 — approximately 18 quintillion — making an accidental collision astronomically unlikely. So 8 bytes is our anchor for 100% confidence, and everything else scales linearly from there.

| Magic length | Keyspace | Confidence |
|---|---|---|
| 2 bytes | 65,536 | 25% |
| 3 bytes | 16,777,216 | 37% |
| 4 bytes | 4,294,967,296 | 50% |
| 6 bytes | 281 trillion | 75% |
| 8+ bytes | 18+ quintillion | 100% |

Text-pattern signatures (shebangs, XML declarations, etc.) use the same formula but are capped at 80%, because they rely on substring matching within the first 512 bytes — inherently fuzzier than exact-offset binary comparisons.

When multiple candidates match, they are sorted by confidence descending. The user sees the most specific match first.

## Supported formats

70+ file formats across these categories:

- **Images:** PNG, JPEG, GIF, BMP, WebP, TIFF, ICO
- **Documents:** PDF, ZIP family (ZIP/JAR/DOCX/APK), OLE2, RTF, CHM
- **Executables:** ELF, PE, Mach-O, Java class, DEX, AutoIt3
- **Archives:** GZIP, BZIP2, XZ, 7z, RAR, Zstd, LZ4, TAR, CAB, CPIO
- **Disk images:** ISO 9660, QCOW2, VHDX, SquashFS, ext2/3/4, NTFS
- **Network:** PCAP, PCAPNG
- **Forensic:** Registry hives, event logs, crash dumps, prefetch, LNK shortcuts
- **Crypto:** PKCS#12, Java KeyStore, PGP, SSH keys, PEM
- **Media:** SQLite, MP3, MP4, WAV, FLAC, OGG, MKV/WebM, AVI, SWF
- **Scripts:** Bash, Python, Perl, Ruby, Node.js, PHP, PowerShell, VBScript
- **Markup:** XML, HTML, HTA, Windows Script Files

Run `magicmatch --list` for the full list.
