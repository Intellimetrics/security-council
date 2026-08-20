"""Read the source window around a finding location and hash it."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Snippet:
    text: str            # the exact lines [start,end] (empty when redacted)
    sha256: str          # sha256 of those lines (survives redaction)
    raw_context: list[str]  # raw +-pad window, for fingerprint.context_hash
    truncated: bool


def capture(path: str, start: int, end: int, *, repo_root: str | Path,
            pad: int = 3, max_chars: int = 4000, redact: bool = False) -> Snippet | None:
    """Return the snippet, or None if the location does not resolve to real code.

    None is a signal: a location that can't be captured is a hallucinated
    location, and the caller drops the finding (and counts it).
    """
    root = Path(repo_root).resolve()
    fpath = (root / path).resolve()
    try:
        fpath.relative_to(root)          # reject traversal escapes
    except ValueError:
        return None
    if not fpath.is_file():
        return None
    lines = fpath.read_text(errors="replace").splitlines()
    if start < 1 or start > len(lines):
        return None
    s = max(1, start)
    e = min(len(lines), max(start, end))
    body = "\n".join(lines[s - 1:e])
    sha = hashlib.sha256(body.encode("utf-8")).hexdigest()
    window = lines[max(0, s - 1 - pad):min(len(lines), e + pad)]
    return Snippet(
        text="" if redact else body[:max_chars],
        sha256=sha,
        raw_context=window,
        truncated=len(body) > max_chars,
    )
