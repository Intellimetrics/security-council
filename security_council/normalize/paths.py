"""Repo-relative POSIX path normalization for finding locations."""

from __future__ import annotations

from pathlib import Path
from urllib.parse import unquote, urlparse


def to_repo_relative(uri: str, *, repo_root: str | Path, scan_root: str | Path | None = None) -> str:
    """Normalize a producer's file URI to a repo-relative POSIX path.

    Handles file:// URIs, backslashes, an absolute scan-mount prefix
    (e.g. a container's ``/src``), and absolute paths under the repo. Traversal
    is not resolved here — a returned ``../x`` is caught by model invariant I1.
    """
    p = uri
    if p.startswith("file://"):
        p = unquote(urlparse(p).path)
    p = p.replace("\\", "/")
    for base in (scan_root, repo_root):
        if not base:
            continue
        b = str(base).replace("\\", "/").rstrip("/")
        if p == b:
            p = ""
        elif p.startswith(b + "/"):
            p = p[len(b) + 1:]
    p = p.lstrip("/")
    while p.startswith("./"):
        p = p[2:]
    return p
