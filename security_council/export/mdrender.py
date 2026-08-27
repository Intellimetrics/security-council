"""Strict renderer for security-council's OWN markdown dialect → HTML fragments.

Why this exists: `summary.md` is the real report (every section, every guard
rail's provenance), and the HTML page used to be a second, hand-maintained
exporter that lagged it by five sections. Rendering the HTML body FROM the
markdown makes drift impossible by construction: whatever `markdown.py` adds
is on the page.

This is not a general markdown engine. It understands exactly what
`markdown.py` emits — headings, `- ` lists (one nesting level per two
spaces), pipe tables with a `|---|` separator row, backtick fences of any
length, `> ` quotes, paragraphs, `**bold**`, `` `code` ``, template-only
`_italics_`, and the `\\X` escapes `markdown._esc` produces — and nothing
else. No links, no raw HTML, no images, no autolinks: a repository's hostile
text has already been neutralised at the markdown boundary, and every text
node here still passes through ONE `html.escape` call, so a tag can never
re-form. No JavaScript is emitted.
"""

from __future__ import annotations

import html
import re

_FENCE_RE = re.compile(r"^(`{3,})([A-Za-z0-9_+.\-]*)\s*$")
_HEADING_RE = re.compile(r"^(#{1,4}) (.*)$")
_TABLE_SEP_RE = re.compile(r"^\|(?:\s*:?-{3,}:?\s*\|)+\s*$")
_LIST_RE = re.compile(r"^( *)- (.*)$")
_CELL_SPLIT_RE = re.compile(r"(?<!\\)\|")
_SEV_WORDS = ("critical", "high", "medium", "low", "info")
_ITALIC_CLOSE_FOLLOW = " .,;:)!?…"


def e(text: object) -> str:
    """THE escaping boundary for every text node this module emits."""
    return html.escape("" if text is None else str(text), quote=True)


_LINK_RE = re.compile(r"\[([^\]\n]+)\]\(([^)\s]+)\)")


def _safe_href(href: str) -> str | None:
    """Relative paths and http(s) only; everything else is rendered as text."""
    h = href.strip()
    low = h.lower()
    if low.startswith(("http://", "https://")):
        return h
    # anything scheme-shaped that is not http(s) — mailto:, file:, data:,
    # javascript:, `//host` — is text, not a link (R14)
    if low.startswith(("//", "\\\\")) or re.match(r"^[a-z][a-z0-9+.\-]*:", low):
        return None
    return h


def inline(text: str, *, allow_links: bool = False) -> str:
    """Render inline markup. Escapes (`\\X`) win over every marker.
    ``allow_links`` renders `[text](href)` — for TRUSTED documentation only;
    reports never set it (a hostile repo must not plant links in a report)."""
    out: list[str] = []
    i, n, bold = 0, len(text), False
    while i < n:
        c = text[i]
        if allow_links and c == "[":
            m = _LINK_RE.match(text, i)
            href = _safe_href(m.group(2)) if m else None
            if m and href is not None:
                out.append(f'<a href="{e(href)}">{inline(m.group(1))}</a>')
                i = m.end()
                continue
        if c == "\\" and i + 1 < n:
            out.append(e(text[i + 1]))
            i += 2
            continue
        if c == "`":
            j = text.find("`", i + 1)
            if j == -1:
                out.append(e(c))
                i += 1
                continue
            out.append(f"<code>{e(text[i + 1:j])}</code>")
            i = j + 1
            continue
        if text.startswith("**", i):
            if bold:
                out.append("</strong>")
                bold = False
                i += 2
                continue
            j = text.find("**", i + 2)
            if j == -1:
                out.append(e("**"))
                i += 2
                continue
            inner = text[i + 2:j]
            if inner.lower() in _SEV_WORDS and inner == inner.upper():
                out.append(f'<strong class="sev {inner.lower()}">{e(inner)}</strong>')
                i = j + 2
                continue
            out.append("<strong>")
            bold = True
            i += 2
            continue
        if c == "_" and (i == 0 or text[i - 1] in " (") and i + 1 < n and text[i + 1] != " ":
            j = _italic_close(text, i + 1)
            if j != -1:
                out.append("<em>" + inline(text[i + 1:j]) + "</em>")
                i = j + 1
                continue
        out.append(e(c))
        i += 1
    if bold:
        out.append("</strong>")
    return "".join(out)


def _italic_close(text: str, start: int) -> int:
    """Index of the `_` that closes an italic span opened just before
    ``start``, or -1. A closer is an unescaped `_` followed by end/space/
    punctuation — so `needs_human` inside the span never closes it."""
    j = start
    n = len(text)
    while True:
        j = text.find("_", j)
        if j == -1:
            return -1
        escaped = j > 0 and text[j - 1] == "\\"
        if not escaped and (j + 1 == n or text[j + 1] in _ITALIC_CLOSE_FOLLOW):
            return j
        j += 1


def _slug(text: str, seen: dict[str, int]) -> str:
    base = re.sub(r"[^a-z0-9]+", "-", re.sub(r"\\.", "", text).lower()).strip("-")[:60] or "s"
    n = seen.get(base, 0)
    seen[base] = n + 1
    return base if n == 0 else f"{base}-{n}"


def _cells(row: str) -> list[str]:
    body = row.strip()
    if body.startswith("|"):
        body = body[1:]
    if body.endswith("|") and not body.endswith("\\|"):
        body = body[:-1]
    return [c.strip() for c in _CELL_SPLIT_RE.split(body)]


def _table(rows: list[str], inl=inline) -> str:
    parsed = [_cells(r) for r in rows]
    has_header = len(rows) >= 2 and bool(_TABLE_SEP_RE.match(rows[1]))
    out = ['<div class="tbl"><table>']
    body = parsed
    if has_header:
        out.append("<thead><tr>" + "".join(f"<th>{inl(c)}</th>" for c in parsed[0])
                   + "</tr></thead>")
        body = parsed[2:]
    if body:
        out.append("<tbody>")
        for r in body:
            out.append("<tr>" + "".join(f"<td>{inl(c)}</td>" for c in r) + "</tr>")
        out.append("</tbody>")
    out.append("</table></div>")
    return "".join(out)


def _list(items: list[tuple[int, str]], inl=inline) -> str:
    """Nested <ul> from (depth, text) items; depth = indent // 2."""
    out: list[str] = []
    depth = -1
    for d, text in items:
        while depth < d:
            out.append("<ul>")
            depth += 1
        while depth > d:
            out.append("</li></ul>")
            depth -= 1
            # the enclosing <li> stays open for siblings; closed by the next
            # sibling's "</li>" or the final unwinding below
        if out and out[-1] not in ("<ul>",) and not out[-1].endswith("</ul>"):
            out.append("</li>")
        elif out and out[-1].endswith("</ul>"):
            out.append("</li>")
        out.append(f"<li>{inl(text)}")
    while depth >= 0:
        out.append("</li></ul>")
        depth -= 1
    return "".join(out)


def render(md: str, *, allow_links: bool = False) -> tuple[str, list[tuple[int, str, str]]]:
    """Render a whole document. Returns (html_body, headings) where headings
    is a list of (level, id, text) for a table of contents. ``allow_links``
    is for trusted documentation only (see `inline`)."""
    _inl = (lambda t: inline(t, allow_links=True)) if allow_links else inline
    lines = md.split("\n")
    out: list[str] = []
    headings: list[tuple[int, str, str]] = []
    seen: dict[str, int] = {}
    para: list[str] = []
    i = 0

    def flush() -> None:
        if para:
            out.append("<p>" + _inl(" ".join(para)) + "</p>")
            para.clear()

    while i < len(lines):
        ln = lines[i]
        m = _FENCE_RE.match(ln)
        if m:
            flush()
            fence, lang = m.group(1), m.group(2)
            body: list[str] = []
            i += 1
            while i < len(lines):
                cl = lines[i].rstrip()
                if cl and set(cl) == {"`"} and len(cl) >= len(fence):
                    break
                body.append(lines[i])
                i += 1
            i += 1
            cls = f' class="lang-{e(lang)}"' if lang else ""
            out.append(f"<pre><code{cls}>{e(chr(10).join(body))}</code></pre>")
            continue
        if not ln.strip():
            flush()
            i += 1
            continue
        m = _HEADING_RE.match(ln)
        if m:
            flush()
            level, text = len(m.group(1)), m.group(2).strip()
            hid = _slug(text, seen)
            headings.append((level, hid, text))
            out.append(f'<h{level} id="{hid}">{_inl(text)}</h{level}>')
            i += 1
            continue
        if ln.lstrip().startswith("|"):
            flush()
            rows = []
            while i < len(lines) and lines[i].lstrip().startswith("|"):
                rows.append(lines[i])
                i += 1
            out.append(_table(rows, _inl))
            continue
        m = _LIST_RE.match(ln)
        if m:
            flush()
            items: list[tuple[int, str]] = []
            while i < len(lines):
                lm = _LIST_RE.match(lines[i])
                if not lm:
                    break
                items.append((len(lm.group(1)) // 2, lm.group(2)))
                i += 1
            out.append(_list(items, _inl))
            continue
        if ln.startswith("> "):
            flush()
            q = []
            while i < len(lines) and lines[i].startswith("> "):
                q.append(lines[i][2:])
                i += 1
            out.append("<blockquote><p>" + _inl(" ".join(q)) + "</p></blockquote>")
            continue
        para.append(ln.strip())
        i += 1
    flush()
    return "\n".join(out), headings
