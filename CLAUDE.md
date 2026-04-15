# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

`magicmatch` is a Python CLI tool that identifies file types by inspecting their **magic bytes** — sequences of bytes at known offsets within a file that act as a reliable fingerprint, independent of file extension. The project is intentionally implemented from scratch (no `python-magic` / `libmagic` wrapper) so the internals are fully understandable for interview purposes.

## Commands

Install in editable mode (run once after cloning):
```bash
pip install -e ".[dev]"
```

Run the tool:
```bash
magicmatch path/to/file          # identify one file
magicmatch path/to/file --verbose  # show matched bytes in hex
magicmatch --help
```

Run tests:
```bash
pytest                                      # all tests
pytest tests/test_detector.py              # one module
pytest tests/test_detector.py::test_png   # one test
pytest -v                                  # verbose output
```

Lint and format:
```bash
ruff check .        # lint
ruff format .       # auto-format
ruff check --fix .  # auto-fix lint issues
```

## Architecture

```
magicmatch/
├── src/magicmatch/
│   ├── signatures.py   # The signature registry: all magic byte patterns live here
│   ├── detector.py     # Core logic: reads file bytes, matches against registry
│   └── cli.py          # argparse CLI; thin layer over detector.py
└── tests/
    ├── fixtures/       # Minimal binary files used as test inputs
    └── test_*.py
```

### Data flow

```
CLI (cli.py) → Detector.identify(path) → reads N bytes from file
                                        → iterates signatures registry
                                        → returns Match(name, mime_type, ext)
```

### Key design decisions

**`signatures.py` — the registry**
Each entry is a `Signature` dataclass:
- `name` — human-readable format name (e.g., `"PNG image"`)
- `mime_type` — IANA MIME type (e.g., `"image/png"`)
- `magic` — `bytes` object with the expected byte sequence
- `offset` — byte offset where the magic appears (almost always `0`, but not always — e.g., some archive formats embed a signature mid-file)

Signatures are stored in a list ordered from most-specific to least-specific, because matching stops at the first hit.

**`detector.py` — the matcher**
Opens the file in binary mode (`"rb"`), reads only as many bytes as needed (`max(offset + len(magic))` across all signatures), then checks each signature with a slice comparison. This avoids loading large files into memory.

**`cli.py` — the entry point**
Registered in `pyproject.toml` as a console script so `magicmatch` is available on `$PATH` after install. Uses `argparse`; keeps no business logic — all detection is delegated to `detector.py`.

### Interview talking points

- **Why magic bytes and not extensions?** Extensions are metadata that can be wrong, renamed, or missing. Magic bytes are embedded in the file's actual content by the program that wrote it.
- **Why read only the minimum bytes?** Efficiency — a 4 GB video file shouldn't need to be fully read just to identify it as MP4.
- **Why order signatures most-specific first?** Some formats share a common prefix (e.g., several Office formats start with the same OLE2 header). Putting the narrower match first avoids false positives.
- **Why a dataclass for `Signature` instead of a dict?** Type safety and IDE autocomplete during development; also makes the code more self-documenting.
