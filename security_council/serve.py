"""`security-council serve` — a read-only viewer for a target's run reports.

What it serves (stdlib `http.server`, no dependency, no JavaScript):

    /                         index: every run newest-first (the `runs` listing)
    /runs/<id>/               that run's summary.html (rendered in memory if absent)
    /runs/<id>/<file>         any file in the run directory (SARIF, findings, raw/…)
    /runs/<id>.zip            the run directory as one download
    /runs/latest/…            redirects to the newest run
    /docs/, /docs/<page>.md   the user documentation, rendered, when a docs dir exists

Trust boundary — read this before changing anything here. A run directory
holds source excerpts, exploit reasoning and secret-adjacent strings, so
turning "files on disk" into "a socket" widens the data boundary
(docs/data-boundaries.md). The rules, all tested:

- **Loopback by default.** Binding anything other than a loopback address
  REQUIRES a token: every request must carry it (`?token=` once, then the
  cookie it sets). Without one the server refuses to start. `DEPLOY_MODE=secret`
  refuses non-loopback binds outright.
- **Read-only, GET/HEAD only.** Nothing writes; nothing executes.
- **Confined.** Every path resolves inside the runs root (or the docs root)
  after following symlinks; `..`, absolute paths and symlink escapes are 404.
  The decision store, `store.json` and `allowed_signers` live outside the runs
  root and are never reachable.
- **Dual-use artifacts stay home.** Files under an `export_excluded` artifact's
  directory are 403 unless `include_dual_use=True` — the same rule the
  exporters apply.
- **Hardened responses.** `Content-Security-Policy: default-src 'none';
  style-src 'unsafe-inline'`, `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: no-referrer`, `Cache-Control: no-store`; markdown and JSON
  are served as text, never sniffed into HTML.
- **A viewer, not a portal.** No accounts, no persistence, no uploads; it
  dies with the process (the MCP `sc_serve` lifetime is the assistant's
  session — for a team portal run the CLI under a supervisor, or publish
  `summary.html` + `exports/` as CI artifacts, which the templates already do).
"""

from __future__ import annotations

import hmac
import html
import io
import ipaddress
import json
import mimetypes
import os
import secrets
import threading
import zipfile
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, urlsplit

from .export import mdrender

DEFAULT_PORT = 8642
COOKIE = "sc_token"
_TEXT_TYPES = {".md": "text/markdown; charset=utf-8", ".sarif": "application/json",
               ".json": "application/json", ".txt": "text/plain; charset=utf-8",
               ".log": "text/plain; charset=utf-8", ".patch": "text/plain; charset=utf-8",
               ".diff": "text/plain; charset=utf-8", ".html": "text/html; charset=utf-8",
               ".csv": "text/csv; charset=utf-8", ".yaml": "text/plain; charset=utf-8",
               ".yml": "text/plain; charset=utf-8", ".toml": "text/plain; charset=utf-8",
               ".cklb": "application/json", ".xml": "text/plain; charset=utf-8"}

_CSS = """
body{margin:0;color:#1a1f27;background:#fff;font:15px/1.5 system-ui,sans-serif}
@media(prefers-color-scheme:dark){body{color:#e6e9ef;background:#12151a}a{color:#8ab8ff}
 code,pre{background:#1b2028}th{background:#1b2028}td,th{border-color:#2c3340}}
.page{max-width:70rem;margin:0 auto;padding:1.5rem 1rem 3rem}
table{border-collapse:collapse;width:100%}td,th{border:1px solid #d8dde5;padding:.35rem .55rem;
text-align:left;font-size:.92rem;vertical-align:top}th{background:#f5f7fa}
code,pre{font-family:ui-monospace,Consolas,monospace;background:#f5f7fa;padding:.1em .35em;border-radius:4px}
pre{padding:.7rem .9rem;overflow-x:auto}.mut{color:#6b7480;font-size:.9rem}
.fail{color:#b3271e;font-weight:700}.pass{color:#2f7d4f;font-weight:700}.warn{color:#8a6d1a;font-weight:700}
"""


def is_loopback(bind: str) -> bool:
    if bind in ("localhost", ""):
        return True
    try:
        return ipaddress.ip_address(bind).is_loopback
    except ValueError:
        return False


def needs_token(bind: str) -> bool:
    return not is_loopback(bind)


class ServeRefused(Exception):
    """The requested bind/token combination is not allowed."""


def check_bind(bind: str, token: str | None) -> None:
    """The one place the exposure policy lives."""
    if not is_loopback(bind):
        if os.environ.get("DEPLOY_MODE", "").lower() == "secret":
            raise ServeRefused("DEPLOY_MODE=secret: the report viewer may only bind a loopback "
                               "address here")
        if not token:
            raise ServeRefused(f"binding {bind!r} exposes the reports beyond this machine; a "
                               "token is required (--token auto generates one)")


def _e(v: object) -> str:
    return html.escape("" if v is None else str(v), quote=True)


def _page(title: str, body: str) -> bytes:
    return (f"<!doctype html><html lang='en'><head><meta charset='utf-8'>"
            f"<meta name='viewport' content='width=device-width,initial-scale=1'>"
            f"<title>{_e(title)}</title><style>{_CSS}</style></head><body><div class='page'>"
            f"{body}</div></body></html>").encode()


class ReportServer:
    """Owns the socket and the policy; `Handler` below does the routing."""

    def __init__(self, target: str | Path, *, bind: str = "127.0.0.1", port: int = DEFAULT_PORT,
                 token: str | None = None, include_dual_use: bool = False,
                 docs_root: str | Path | None = None) -> None:
        self.target = Path(target).resolve()
        self.runs_root = self.target / ".security-council" / "runs"
        self.bind = bind
        if token == "auto":
            token = secrets.token_urlsafe(24)
        check_bind(bind, token)
        self.token = token or None
        self.include_dual_use = include_dual_use
        self.docs_root = Path(docs_root).resolve() if docs_root else _default_docs_root()
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self.port = port

    # -- lifecycle ---------------------------------------------------------
    def start(self) -> str:
        server = self
        from .cli import run_dirs

        class Handler(_Handler):
            srv = server
            _run_dirs = staticmethod(run_dirs)

        self._httpd = ThreadingHTTPServer((self.bind, self.port), Handler)
        self._httpd.daemon_threads = True
        self.port = self._httpd.server_address[1]
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True,
                                        name="security-council-serve")
        self._thread.start()
        return self.url

    def stop(self) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None

    @property
    def running(self) -> bool:
        return self._httpd is not None

    @property
    def url(self) -> str:
        host = (_lan_address() or "127.0.0.1") if self.bind in ("0.0.0.0", "::", "") \
            else self.bind
        base = f"http://{host}:{self.port}/"
        return base + (f"?token={self.token}" if self.token else "")

    # -- policy helpers used by the handler --------------------------------
    def excluded_dirs(self, run_dir: Path) -> list[Path]:
        """RESOLVED directories holding dual-use (export_excluded) artifacts,
        from the run's manifest. Compared as resolved paths, never as request
        strings — a symlink alias or a case-insensitive filesystem would
        otherwise walk around a prefix check (R14 own pass). Read per request:
        manifests are small and a run can be re-rendered while the viewer is up."""
        if self.include_dual_use:
            return []
        try:
            m = json.loads((run_dir / "manifest.json").read_text())
        except (OSError, ValueError):
            return []
        out: list[Path] = []
        for a in m.get("artifacts") or []:
            if a.get("export_excluded") and a.get("path"):
                d = _confine(run_dir, str(a["path"]).strip("/").rsplit("/", 1)[0]
                             if "/" in str(a["path"]) else "")
                if d is not None and d != run_dir.resolve():
                    out.append(d)
        return out

    @staticmethod
    def is_excluded(path: Path, excluded: list[Path]) -> bool:
        try:
            r = path.resolve(strict=True)
        except OSError:
            return False
        return any(r == d or d in r.parents for d in excluded)


def _default_docs_root() -> Path | None:
    cand = Path(__file__).resolve().parents[1] / "docs"
    return cand if (cand / "README.md").is_file() else None


def _lan_address() -> str | None:
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 1))
        addr = s.getsockname()[0]
        s.close()
        return addr
    except OSError:
        return None


def _confine(root: Path, rel: str) -> Path | None:
    """The path under ``root`` that ``rel`` names, or None if it escapes —
    after resolving symlinks, so a link inside the tree cannot point out."""
    if not rel or rel.startswith("/") or "\\" in rel or "\x00" in rel:
        return None if rel else root
    parts = [p for p in rel.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        return None
    cand = root.joinpath(*parts) if parts else root
    try:
        resolved = cand.resolve(strict=True)
        rroot = root.resolve(strict=True)
    except OSError:
        return None
    if resolved != rroot and rroot not in resolved.parents:
        return None
    return resolved


class _Handler(BaseHTTPRequestHandler):
    srv: ReportServer
    server_version = "security-council-serve"
    sys_version = ""

    # -- plumbing ---------------------------------------------------------
    def log_message(self, fmt, *args):  # noqa: D401 - quiet by default
        if os.environ.get("SECURITY_COUNCIL_SERVE_LOG"):
            super().log_message(fmt, *args)

    def _send(self, status: int, body: bytes, ctype: str, extra: dict | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; "
                         "form-action 'none'; base-uri 'none'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _err(self, status: HTTPStatus, msg: str) -> None:
        self._send(status, _page(f"{status.value} {status.phrase}",
                                 f"<h1>{status.value} {_e(status.phrase)}</h1><p>{_e(msg)}</p>"),
                   "text/html; charset=utf-8")

    def _authorized(self, query: dict) -> tuple[bool, dict]:
        """(ok, extra headers). A token in the query sets the cookie so links
        inside the pages (which carry no token) keep working."""
        tok = self.srv.token
        if not tok:
            return True, {}
        presented = (query.get("token") or [None])[0]
        if presented is not None:
            if hmac.compare_digest(presented, tok):
                return True, {"Set-Cookie": f"{COOKIE}={quote(tok)}; HttpOnly; SameSite=Strict; Path=/"}
            return False, {}
        cookies = self.headers.get("Cookie", "")
        for part in cookies.split(";"):
            k, _, v = part.strip().partition("=")
            if k == COOKIE and hmac.compare_digest(v, tok):
                return True, {}
        return False, {}

    # -- routing ----------------------------------------------------------
    def do_HEAD(self):  # noqa: N802
        self.do_GET()

    def do_GET(self):  # noqa: N802
        url = urlsplit(self.path)
        query = parse_qs(url.query)
        ok, extra = self._authorized(query)
        if not ok:
            self._err(HTTPStatus.UNAUTHORIZED, "this viewer requires its token: open the URL "
                                                "that `security-council serve` printed")
            return
        self._extra = extra
        path = url.path
        try:
            if path == "/":
                return self._index()
            if path == "/runs/latest" or path.startswith("/runs/latest/"):
                return self._latest(path)
            if path.startswith("/runs/"):
                return self._run(path[len("/runs/"):])
            if path == "/docs" or path.startswith("/docs/"):
                return self._docs(path[len("/docs"):].lstrip("/"))
            self._err(HTTPStatus.NOT_FOUND, "no such page")
        except BrokenPipeError:
            pass

    def _index(self) -> None:
        rows = []
        for d in self._run_dirs(self.srv.target):
            try:
                m = json.loads((d / "manifest.json").read_text())
            except (OSError, ValueError):
                continue
            code = m.get("exit_code")
            cls = {0: "pass", 1: "fail"}.get(code, "warn")
            sev = (m.get("counts") or {}).get("by_severity") or {}
            rows.append(
                f"<tr><td><a href='/runs/{_e(d.name)}/'>{_e(d.name)}</a></td>"
                f"<td class='{cls}'>exit {_e(code)}</td>"
                f"<td>{_e((m.get('counts') or {}).get('total'))}</td>"
                f"<td>{_e(' '.join(f'{k}={v}' for k, v in sev.items()))}</td>"
                f"<td>{_e(', '.join(a.get('name', '?') for a in m.get('arms') or []))}</td>"
                f"<td>{_e(str(m.get('started_at') or '')[:19])}</td>"
                f"<td><a href='/runs/{_e(d.name)}.zip'>zip</a></td></tr>")
        docs = ("<p><a href='/docs/'>Documentation</a></p>" if self.srv.docs_root else "")
        body = (f"<h1>security-council — {_e(self.srv.target.name)}</h1>"
                f"<p class='mut'>runs under <code>{_e(self.srv.runs_root)}</code> · read-only viewer"
                + (" · token-protected" if self.srv.token else " · loopback only") + "</p>"
                + docs
                + ("<table><tr><th>run</th><th>gate</th><th>findings</th><th>severity</th>"
                   "<th>arms</th><th>started</th><th>download</th></tr>" + "".join(rows)
                   + "</table>" if rows else "<p>No runs yet — run <code>security-council scan .</code>.</p>"))
        self._send(200, _page("security-council", body), "text/html; charset=utf-8", self._extra)

    def _latest(self, path: str) -> None:
        dirs = self._run_dirs(self.srv.target)
        if not dirs:
            return self._err(HTTPStatus.NOT_FOUND, "no runs yet")
        rest = path[len("/runs/latest"):] or "/"
        self._send(HTTPStatus.FOUND, b"", "text/plain",
                   {"Location": f"/runs/{quote(dirs[0].name)}{rest}", **self._extra})

    def _run(self, rel: str) -> None:
        if rel.endswith(".zip") and "/" not in rel:
            return self._zip(rel[:-4])
        run_id, _, inner = rel.partition("/")
        run_dir = _confine(self.srv.runs_root, run_id)
        if run_dir is None or not run_dir.is_dir() or run_dir == self.srv.runs_root.resolve():
            return self._err(HTTPStatus.NOT_FOUND, "no such run")
        if not inner:
            # R14 (codex): the page path must go through the same confinement as
            # every other file — a symlinked summary.html must not be followed out
            page = _confine(run_dir, "summary.html")
            body = (page.read_bytes() if page is not None and page.is_file()
                    else self._render_summary(run_dir))
            if body is None:
                return self._err(HTTPStatus.NOT_FOUND, "this run has no summary")
            return self._send(200, body, "text/html; charset=utf-8", self._extra)
        target = _confine(run_dir, inner)
        if target is None:
            return self._err(HTTPStatus.NOT_FOUND, "no such file")
        if self.srv.is_excluded(target, self.srv.excluded_dirs(run_dir)):
            return self._err(HTTPStatus.FORBIDDEN, "dual-use artifact: not served (start with "
                                                   "--include-dual-use to allow it)")
        if target.is_dir():
            return self._listing(run_dir, target, inner)
        if not target.is_file():
            return self._err(HTTPStatus.NOT_FOUND, "no such file")
        ctype = _TEXT_TYPES.get(target.suffix.lower()) or \
            (mimetypes.guess_type(target.name)[0] or "application/octet-stream")
        if ctype.startswith("text/html") and target.name != "summary.html":
            ctype = "text/plain; charset=utf-8"          # only OUR page renders as HTML
        self._send(200, target.read_bytes(), ctype, self._extra)

    def _listing(self, run_dir: Path, d: Path, inner: str) -> None:
        excluded = self.srv.excluded_dirs(run_dir)
        items = []
        for p in sorted(d.iterdir(), key=lambda x: (not x.is_dir(), x.name)):
            rel = f"{inner.rstrip('/')}/{p.name}".strip("/")
            if self.srv.is_excluded(p, excluded):
                items.append(f"<li>{_e(p.name)} <span class='mut'>(dual-use, not served)</span></li>")
                continue
            if _confine(run_dir, rel) is None:
                items.append(f"<li>{_e(p.name)} <span class='mut'>(not served)</span></li>")
                continue
            items.append(f"<li><a href='/runs/{_e(run_dir.name)}/{_e(rel)}{'/' if p.is_dir() else ''}'>"
                         f"{_e(p.name)}{'/' if p.is_dir() else ''}</a></li>")
        body = (f"<h1>{_e(run_dir.name)} / {_e(inner)}</h1><p><a href='/runs/{_e(run_dir.name)}/'>"
                f"← report</a></p><ul>{''.join(items)}</ul>")
        self._send(200, _page(inner, body), "text/html; charset=utf-8", self._extra)

    def _render_summary(self, run_dir: Path) -> bytes | None:
        """Render a run's page IN MEMORY when summary.html is missing (older
        runs). The viewer never writes into a run directory."""
        try:
            from .cli import _load_findings, _load_scores
            from .export import html_export
            m = json.loads((run_dir / "manifest.json").read_text())
            md = run_dir / "summary.md"
            return html_export.to_html(
                _load_findings(run_dir), m, scores=_load_scores(run_dir) or None, run_dir=run_dir,
                markdown_text=md.read_text() if md.is_file() else None).encode()
        except (OSError, ValueError):
            return None

    def _zip(self, run_id: str) -> None:
        run_dir = _confine(self.srv.runs_root, run_id)
        if run_dir is None or not run_dir.is_dir() or run_dir == self.srv.runs_root.resolve():
            return self._err(HTTPStatus.NOT_FOUND, "no such run")
        excluded = self.srv.excluded_dirs(run_dir)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for p in sorted(run_dir.rglob("*")):
                if not p.is_file() or p.is_symlink():
                    continue
                rel = p.relative_to(run_dir).as_posix()
                # symlinked DIRECTORIES are walked by rglob: confine each file
                if _confine(run_dir, rel) is None or self.srv.is_excluded(p, excluded):
                    continue
                zf.write(p, f"{run_dir.name}/{rel}")
        self._send(200, buf.getvalue(), "application/zip",
                   {"Content-Disposition": f'attachment; filename="{run_dir.name}.zip"', **self._extra})

    def _docs(self, rel: str) -> None:
        root = self.srv.docs_root
        if root is None:
            return self._err(HTTPStatus.NOT_FOUND, "no documentation directory is available here")
        target = _confine(root, rel)
        if target is None:
            return self._err(HTTPStatus.NOT_FOUND, "no such page")
        if target.is_dir():
            target = target / "README.md"
        if not target.is_file():
            return self._err(HTTPStatus.NOT_FOUND, "no such page")
        if target.suffix.lower() != ".md":
            ctype = _TEXT_TYPES.get(target.suffix.lower()) or "text/plain; charset=utf-8"
            if ctype.startswith("text/html"):
                ctype = "text/plain; charset=utf-8"
            return self._send(200, target.read_bytes(), ctype, self._extra)
        body, _ = mdrender.render(target.read_text(), allow_links=True)
        crumb = f"<p class='mut'><a href='/'>runs</a> · <a href='/docs/'>docs</a> · " \
                f"<code>{_e(target.relative_to(root).as_posix())}</code></p>"
        self._send(200, _page(target.stem, crumb + body), "text/html; charset=utf-8", self._extra)
