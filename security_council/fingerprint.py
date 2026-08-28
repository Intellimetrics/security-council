"""Stable finding fingerprints.

Three fingerprints, all shaped `<algo>/v1:<32-hex>` (matching model._FINGERPRINT_RE)
and — critically — **containing no raw line numbers**, so a finding survives code
drift (added blank lines, reformatted or moved comments, renumbering):

- ``path_cwe_sink``  identity: same bug kind at the same place in the same file.
- ``context_hash``   the normalized ±N source window around the sink.
- ``root_cause``     what actually causes it (source symbol + sink expr, or a
                     package+advisory for dependency findings) — the clustering key.

`normalize_line` is the load-bearing function: it strips comments and whitespace,
masks string and numeric *literals* (so their values don't affect identity) while
preserving identifiers and call structure (so real code changes do).
"""

from __future__ import annotations

import hashlib
import re
from typing import Optional

from .model import PackageRef, canonical_cwe

# Whole-line comment / block-body markers (language-agnostic).
_LINE_COMMENT_START = ("#", "//", "--", ";", "*", "/*")
# Trailing comment openers, stripped only AFTER string literals are masked so a
# `//` inside a (now-masked) URL/string is never mistaken for a comment.
_TRAILING_COMMENT_RE = re.compile(r"(#|//|--|/\*).*$")
# Quoted string literals (single/double/backtick) with escapes.
_STRING_RE = re.compile(r"""("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`)""")
_HEX_RE = re.compile(r"\b0[xX][0-9a-fA-F]+\b")
_NUM_RE = re.compile(r"(?<![A-Za-z0-9_])\d+(?:\.\d+)?")
_WS_RE = re.compile(r"\s+")


def normalize_line(line: str) -> Optional[str]:
    """Normalize one source line for hashing, or None if it carries no code.

    Returns None for blank lines and whole-line comments (so they never affect
    the hash). Otherwise: whitespace collapsed, trailing comments removed, string
    literals -> S, numeric literals -> N, identifiers/operators preserved.
    """
    s = _WS_RE.sub(" ", line.strip())
    if not s:
        return None
    if s.startswith(_LINE_COMMENT_START):
        return None
    s = _STRING_RE.sub("S", s)          # mask string values first...
    s = _TRAILING_COMMENT_RE.sub("", s)  # ...then trailing comments are safe to cut
    s = s.strip()
    if not s:
        return None
    s = _HEX_RE.sub("N", s)
    s = _NUM_RE.sub("N", s)
    return s


def normalized_window(lines: list[str]) -> list[str]:
    """Normalize a window of raw source lines, dropping the no-code ones."""
    out = []
    for ln in lines:
        n = normalize_line(ln)
        if n is not None:
            out.append(n)
    return out


def _digest(parts: list[str]) -> str:
    payload = "\x00".join(parts)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:32]


def _norm_path(path: str) -> str:
    from .normalize.paths import normalize_separators   # lazy: normalize.base imports us
    return normalize_separators(path.strip()).lstrip("./")


def _norm_expr(expr: str) -> str:
    return normalize_line(expr) or expr.strip()


def path_cwe_sink(*, path: str, cwe: str, sink_token: str) -> str:
    """Identity fingerprint. `sink_token` is (preferred) the enclosing symbol, else
    the normalized sink line, else the rule id — chosen by the caller."""
    body = _digest(["pathCweSink/v1", _norm_path(path), canonical_cwe(cwe), sink_token.strip()])
    return f"pathCweSink/v1:{body}"


def context_hash(lines: list[str]) -> str:
    """Line-drift-resistant hash of the normalized ±N window around the sink."""
    body = _digest(["contextHash/v1", "\n".join(normalized_window(lines))])
    return f"contextHash/v1:{body}"


def root_cause(
    *,
    cwe_family: str,
    root_symbol: str,
    sink_expr: str,
    package: Optional[PackageRef] = None,
) -> str:
    """Root-cause clustering key. For dependency findings, keyed on
    (package-sans-version, advisory); otherwise on (family, source symbol, sink)."""
    if package is not None:
        advisories = ",".join(sorted(package.advisory_ids)) or "-"
        body = _digest(["rootCause/v1", "pkg", purl_without_version(package.purl), advisories])
    else:
        body = _digest(["rootCause/v1", cwe_family, root_symbol.strip(), _norm_expr(sink_expr)])
    return f"rootCause/v1:{body}"


def purl_without_version(purl: str) -> str:
    """Strip the @version qualifier from a Package URL (pkg:type/ns/name@ver?...)."""
    p = purl.strip()
    # drop qualifiers/subpath first so an '@' in them can't confuse us
    p = p.split("?", 1)[0].split("#", 1)[0]
    at = p.rfind("@")
    slash = p.rfind("/")
    return p[:at] if at > slash else p
