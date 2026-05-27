from __future__ import annotations

from pathlib import Path

from magicmatch.signatures import SIGNATURES, Candidate, Signature


def _binary_confidence(magic: bytes) -> int:
    return min(100, len(magic) * 100 // 8)


def _text_confidence(pattern: bytes) -> int:
    return min(80, len(pattern) * 100 // 8)


class Detector:
    def __init__(self, signatures: list[Signature] | None = None) -> None:
        self._sigs = signatures if signatures is not None else SIGNATURES

    def identify(self, path: str | Path) -> list[Candidate]:
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"No such file: {path}")

        binary_sigs = [s for s in self._sigs if s.mode == "binary"]
        text_sigs = [s for s in self._sigs if s.mode == "text"]

        max_binary = max(
            (s.offset + len(s.magic) for s in binary_sigs),
            default=0,
        )
        read_size = max(max_binary, 512 if text_sigs else 0)

        data = path.read_bytes()[:read_size] if read_size else b""

        candidates: list[Candidate] = []

        for sig in binary_sigs:
            end = sig.offset + len(sig.magic)
            if len(data) >= end and data[sig.offset : end] == sig.magic:
                candidates.append(
                    Candidate(
                        confidence=_binary_confidence(sig.magic),
                        name=sig.name,
                        mime_type=sig.mime_type,
                        extensions=sig.extensions,
                        matched_bytes=sig.magic,
                        offset=sig.offset,
                    )
                )

        for sig in text_sigs:
            window = data[:512]
            if sig.magic in window:
                candidates.append(
                    Candidate(
                        confidence=_text_confidence(sig.magic),
                        name=sig.name,
                        mime_type=sig.mime_type,
                        extensions=sig.extensions,
                        matched_bytes=sig.magic,
                        offset=window.index(sig.magic),
                    )
                )

        candidates.sort(key=lambda c: c.confidence, reverse=True)

        seen: set[tuple[str, str]] = set()
        deduped: list[Candidate] = []
        for c in candidates:
            key = (c.name, c.mime_type)
            if key not in seen:
                seen.add(key)
                deduped.append(c)
        return deduped
