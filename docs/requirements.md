# magicmatch — Project Requirements

## Overview

`magicmatch` is a command-line tool that identifies the type of a file by inspecting its **magic bytes** (binary signatures embedded at known offsets in the file) or **text patterns** (characteristic strings near the start of plain-text files), rather than relying on the file extension.

---

## Functional Requirements

### Core Detection

- Read the minimum number of bytes necessary to identify a file (do not load the entire file into memory).
- Match bytes against a built-in signature registry.
- Produce a **ranked list of candidates**, each with a confidence score (0–100%), rather than a single hard answer.
- Report "unknown" when no candidate scores above the minimum threshold.

#### Two Detection Modes

Not all file types can be identified by binary magic bytes. The detector supports two modes:

| Mode | How it works | Examples |
|---|---|---|
| **Binary signature** | Compares raw bytes at a known offset | ELF, PE, PNG, ZIP, PCAP |
| **Text pattern** | Searches for a characteristic string in the first ~512 bytes | `.sh`, `.bat`, `.ps1`, `.php` |

Text-pattern matching is inherently less reliable than binary signature matching and produces lower confidence scores by design.

#### Confidence Scoring

Identification is probabilistic. A confidence score is calculated per candidate based on:

1. **Byte match depth** — how many consecutive bytes of the signature matched vs. the total signature length. A full match scores higher than a partial one.
2. **Signature specificity** — longer signatures are more specific and are weighted higher than short ones. A 2-byte match on a 2-byte signature is less trustworthy than a 12-byte match on a 12-byte signature.
3. **Offset correctness** — a signature found at its expected offset scores 100% on this factor; finding similar bytes at the wrong offset does not count.
4. **Detection mode penalty** — text-pattern matches are capped at 80% confidence to reflect their lower reliability compared to binary signatures.

By default, only candidates scoring **≥ 30%** are shown, up to a maximum of **3 results**. Both values are configurable via flags.

### CLI Interface

| Invocation | Behaviour |
|---|---|
| `magicmatch <file>` | Identify a single file and print ranked candidates |
| `magicmatch <file> --top N` | Show top N candidates (default: 3) |
| `magicmatch <file> --min-confidence N` | Only show candidates scoring ≥ N% (default: 30) |
| `magicmatch <file> --verbose` | Also print the matched hex bytes and offset for each candidate |
| `magicmatch <file> --json` | Output results as JSON (for scripting) |
| `magicmatch --list` | List all supported formats and their signatures |
| `magicmatch --help` | Show usage |

### Exit Codes

| Code | Meaning |
|---|---|
| `0` | At least one candidate met the confidence threshold |
| `1` | No candidate met the threshold (type unknown) |
| `2` | Error (file not found, permission denied, etc.) |

### Output Format (default)

```
file.png
  100%  PNG image (image/png) [.png]
```

```
ambiguous.bin
   72%  ZIP archive (application/zip) [.zip]
   61%  Java Archive (application/java-archive) [.jar]
   61%  Office Open XML (application/vnd.openxmlformats) [.docx/.xlsx/.pptx]
```

### Output Format (--verbose)

```
file.png
  100%  PNG image (image/png) [.png]
        matched: 89 50 4E 47 0D 0A 1A 0A  at offset 0
```

### Output Format (--json)

```json
{
  "file": "file.png",
  "candidates": [
    {
      "confidence": 100,
      "name": "PNG image",
      "mime_type": "image/png",
      "extension": ".png",
      "matched_bytes": "89504E470D0A1A0A",
      "offset": 0
    }
  ]
}
```

---

## Supported File Formats

### Executables & Bytecode
- ELF — Linux/Unix executables, shared objects (`.so`), core dumps
- PE — Windows executables and libraries (`.exe`, `.dll`, `.sys`, `.drv`)
- Mach-O — macOS/iOS executables (32-bit, 64-bit, and fat/universal binaries)
- Java class file (`.class`) — ⚠ shares magic `CA FE BA BE` with Mach-O fat binary; distinguished by the next 4 bytes (architecture count vs. class file version); signatures must be ordered carefully and both candidates surfaced when ambiguous
- DEX — Android Dalvik Executable (`.dex`)
- Python bytecode (`.pyc`) — versions 3.x
- COFF object file (`.obj`)
- NSIS installer — Nullsoft installer; PE wrapper with `Nullsoft Inst` marker inside
- AutoIt3 compiled script — binary magic `AU3!` at offset 0

### Scripts & Interpreted Languages

These are **plain-text** files with no binary magic bytes. Detection uses text-pattern matching on the first ~512 bytes. Confidence is capped at 80%.

**Unix / cross-platform (identified by shebang `#!`):**
- Bash / sh script (`.sh`) — `#!/bin/bash`, `#!/bin/sh`, `#!/usr/bin/env bash`
- Python script (`.py`) — `#!/usr/bin/env python` or `#!/usr/bin/python`
- Perl script (`.pl`) — `#!/usr/bin/perl`
- Ruby script (`.rb`) — `#!/usr/bin/env ruby`
- Node.js script (`.js`) — `#!/usr/bin/env node`
- PHP script (`.php`) — `<?php` (reliable, no shebang needed)

**Windows-specific (no shebang; identified by common syntax patterns):**
- Windows Batch (`.bat`, `.cmd`) — ⚠ best-effort only; no guaranteed first-line pattern (file may start with blank lines, comments, or any command); low confidence by design
- PowerShell (`.ps1`) — `param(`, `function `, `#Requires`, or `$` variable patterns near the start
- VBScript (`.vbs`) — `Dim `, `WScript.`, `CreateObject(`, `Set ` patterns
- JScript (`.js` on Windows / `.jse`) — `WScript.`, `new ActiveXObject(` patterns
- Windows Script File (`.wsf`) — XML file starting with `<job` or `<package`
- HTA — HTML Application (`.hta`) — `<HTA:APPLICATION` tag; used in living-off-the-land attacks

### Archives & Compression
- ZIP — ⚠ `PK\x03\x04` is shared by the entire ZIP family (see note below)
- GZIP
- BZIP2
- XZ / LZMA
- 7-Zip
- RAR (v4 and v5 — different magic bytes)
- Zstandard (`.zst`)
- LZ4
- TAR — `ustar` signature at offset 257; requires reading 262 bytes
- CAB — Windows Cabinet (`.cab`)
- CPIO archive

### Documents & Office Formats
- PDF
- OLE2 Compound Document — legacy Microsoft Office (`.doc`, `.xls`, `.ppt`), also MSI installers
- Office Open XML (`.docx`, `.xlsx`, `.pptx`) — ⚠ ZIP-based; shares `PK\x03\x04` magic with plain ZIP, JAR, APK; cannot be fully distinguished from magic bytes alone (would require inspecting internal filenames such as `[Content_Types].xml`)
- RTF
- CHM — Windows Compiled HTML Help (historically used in phishing)

> **ZIP family note:** ZIP, DOCX, XLSX, PPTX, JAR, and APK all begin with `PK\x03\x04`. The detector will return all of them as candidates with equal confidence when it sees this header. Distinguishing them requires partial archive inspection, which is out of scope. The output will honestly reflect the ambiguity.

### Disk Images & Filesystems
- ISO 9660 (`.iso`) — ⚠ `CD001` signature is at offset **32,768**; the detector must read 32 KB to reach it, which is the largest offset in the registry and a deliberate exception to the minimum-read rule
- QCOW2 — QEMU/KVM virtual disk
- VHDX — Microsoft Virtual Hard Disk v2
- SquashFS — common in firmware images
- ext2/3/4 — superblock magic at offset **1,080**; requires reading ~1,082 bytes
- NTFS filesystem image — ⚠ low specificity; `NTFS    ` at offset 3 is only 8 bytes; confidence will be lower than other formats

### Network Captures
- PCAP — libpcap format (little-endian and big-endian variants)
- PCAPNG — newer capture format used by Wireshark

### Windows Forensic Artifacts
- Windows Registry Hive (`REGF` magic — `NTUSER.DAT`, `SAM`, `SYSTEM`, `SOFTWARE`, etc.)
- Windows Event Log v1 (`.evt` — legacy)
- Windows Event Log v2 (`.evtx` — modern)
- Windows Crash Dump / Minidump (`.dmp`)
- Windows Prefetch (`.pf`)
- Windows LNK shortcut (`.lnk`)

### Cryptographic & Certificate Formats
- PEM — base64-encoded DER with `-----BEGIN` header (certificates, keys, CSRs); text-pattern match, highly reliable
- DER — raw binary ASN.1 (certificates, keys) — ⚠ best-effort only; starts with `\x30` (ASN.1 SEQUENCE tag), which is extremely common in binary files; will produce low confidence scores and frequent false positives
- PKCS#12 / PFX — bundled certificate + private key (`.pfx`, `.p12`)
- PGP/GPG message or key (binary and ASCII-armored)
- SSH private key — OpenSSH modern format

### Memory & Runtime Artifacts
- Java KeyStore (JKS)
- Android Binary XML (`AXML`) — compiled AndroidManifest.xml
- Android Resources (`ARSC`)

### Firmware & Low-Level
- UEFI firmware volume
- U-Boot image
- Intel HEX (`.hex`) — text-based, identifiable by `:` record prefix

### Databases
- SQLite (v3)

### Images
- PNG
- JPEG
- GIF (87a and 89a)
- BMP
- WebP
- TIFF (little-endian and big-endian)
- ICO — Windows icon file

### Media
- MP3 (ID3 tag and raw frame sync)
- MP4 / M4A
- WAV
- FLAC
- OGG
- Matroska / WebM (`.mkv`, `.webm`)
- AVI
- SWF — Adobe Flash (historically relevant: Flash exploits were common attack vectors)

### Other
- XML / HTML (identified by BOM or `<?xml` / `<!DOCTYPE` / `<html` text prefix)

---

## Non-Functional Requirements

- **No external magic libraries.** Do not wrap `libmagic` or `python-magic`. All detection logic is implemented in Python.
- **Memory efficient.** Only read as many bytes as needed for the deepest offset in the signature registry.
- **Cross-platform.** Must run on Linux, macOS, and Windows.
- **Fast.** Identification of a single file should complete in well under 100 ms.

---

## Out of Scope

- Recursive directory scanning.
- Text encoding or language detection.
- File content validation (e.g., checking whether a PNG is actually a valid, uncorrupted PNG).
- Signature database updates at runtime.
