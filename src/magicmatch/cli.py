from __future__ import annotations

import argparse
import sys
from pathlib import Path

from magicmatch.detector import Detector
from magicmatch.signatures import SIGNATURES, Candidate

BANNER = r"""
                       _                       _       _
  _ __ ___   __ _  __ _(_) ___ _ __ ___   __ _| |_ ___| |__
 | '_ ` _ \ / _` |/ _` | |/ __| '_ ` _ \ / _` | __/ __| '_ \
 | | | | | | (_| | (_| | | (__| | | | | | (_| | || (__| | | |
 |_| |_| |_|\__,_|\__, |_|\___|_| |_| |_|\__,_|\__\___|_| |_|
                   |___/
"""


def _fmt_extensions(extensions: list[str]) -> str:
    exts = [e for e in extensions if e]
    if not exts:
        return ""
    return "[" + "/".join(exts) + "]"


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="magicmatch",
        description="Identify file types by inspecting magic bytes.",
    )
    parser.add_argument("file", nargs="?", help="File to identify")
    parser.add_argument("--top", type=int, default=3, metavar="N",
                        help="Show top N candidates (default: 3)")
    parser.add_argument("--min-confidence", type=int, default=30, metavar="N",
                        help="Minimum confidence %% to show (default: 30)")
    parser.add_argument("--verbose", action="store_true",
                        help="Show matched hex bytes and offset")
    parser.add_argument("--json", action="store_true",
                        help="Output results as JSON")
    parser.add_argument("--list", action="store_true",
                        help="List all supported formats")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="Suppress the banner")
    args = parser.parse_args(argv)

    if args.list:
        for sig in SIGNATURES:
            exts = " ".join(sig.extensions) if sig.extensions else "-"
            print(f"{sig.name:<45} {sig.mime_type:<50} {exts}")
        sys.exit(0)

    if not args.file:
        parser.print_help()
        sys.exit(2)

    path = Path(args.file)

    try:
        candidates = Detector().identify(path)
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(2)

    candidates = [c for c in candidates if c.confidence >= args.min_confidence]

    if args.json:
        import json
        output = {
            "file": str(path),
            "candidates": [
                {
                    "confidence": c.confidence,
                    "name": c.name,
                    "mime_type": c.mime_type,
                    "extensions": c.extensions,
                    "matched_bytes": c.matched_bytes.hex().upper(),
                    "offset": c.offset,
                }
                for c in candidates[: args.top]
            ],
        }
        print(json.dumps(output, indent=2))
        sys.exit(0 if candidates else 1)

    if not args.quiet:
        print(BANNER)

    if not candidates:
        print(path.name)
        print("  Unknown file type")
        sys.exit(1)

    print(path.name)
    for c in candidates[: args.top]:
        exts = _fmt_extensions(c.extensions)
        line = f"  {c.confidence:3d}%  {c.name} ({c.mime_type})"
        if exts:
            line += f" {exts}"
        print(line)
        if args.verbose:
            hex_bytes = " ".join(f"{b:02X}" for b in c.matched_bytes)
            print(f"          matched: {hex_bytes}  at offset {c.offset}")

    sys.exit(0)


if __name__ == "__main__":
    main()
