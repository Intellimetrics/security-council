"""Repo-relative POSIX path normalization for finding locations."""

from __future__ import annotations

import os
import re
from pathlib import Path
from urllib.parse import unquote, urlparse

_WINDOWS_SHAPED = re.compile(r"^(?:[A-Za-z]:[\\/]|\\\\)")
_DRIVE_AFTER_SLASH = re.compile(r"^/[A-Za-z]:/")


def normalize_separators(path: str) -> str:
    r"""Translate ``\`` to ``/`` only where a backslash IS a separator: on a
    Windows host, or in a Windows-shaped path (drive letter or UNC prefix).

    On POSIX a backslash is a legal filename character. R15 (0.2.0 release
    rehearsal) reproduced a committed file literally named ``app\\reports.py``
    normalizing onto ``app/reports.py``: its findings were folded into the
    original's location (invisible in the report) and the baseline delta read
    the copy as ``unchanged`` — a silent gate pass. The scanned repository must
    not be able to alias one of its files onto another."""
    if os.name == "nt" or _WINDOWS_SHAPED.match(path):
        return path.replace("\\", "/")
    return path


def to_repo_relative(uri: str, *, repo_root: str | Path, scan_root: str | Path | None = None) -> str:
    """Normalize a producer's file URI to a repo-relative POSIX path.

    Handles file:// URIs, backslashes, an absolute scan-mount prefix
    (e.g. a container's ``/src``), and absolute paths under the repo. Traversal
    is not resolved here — a returned ``../x`` is caught by model invariant I1.
    """
    p = uri
    if p.startswith("file://"):
        u = urlparse(p)
        p = unquote(u.path)
        if u.netloc:
            p = "//" + u.netloc + p                    # UNC: keep the authority
        elif _DRIVE_AFTER_SLASH.match(p):
            p = p[1:]                                  # file:///C:/x -> C:/x
    p = normalize_separators(p)
    absolute = p.startswith("/") or bool(_WINDOWS_SHAPED.match(p))
    matched = False
    for base in (scan_root, repo_root):
        if not base:
            continue
        b = normalize_separators(str(base)).rstrip("/")
        if p == b:
            p, matched = "", True
        elif p.startswith(b + "/"):
            p, matched = p[len(b) + 1:], True
    if absolute and not matched:
        # R15b: an absolute path that no configured base explains used to be
        # made "relative" by stripping its leading slashes — `C:\src\app.py` →
        # `C:/src/app.py`, `\\srv\share\x.py` → `srv/share/x.py`, `/etc/passwd`
        # → `etc/passwd` — and a hostile repository containing that tree would
        # place the finding there. Leave it absolute: invariant I1 refuses it,
        # the finding is dropped and COUNTED (partial_coverage), never aliased.
        return p
    p = p.lstrip("/")
    while p.startswith("./"):
        p = p[2:]
    return p
