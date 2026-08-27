"""`security-council serve`: a read-only viewer over a socket.

The socket widens the data boundary from files to the network, so what is
tested here is the POLICY: loopback-by-default, token-or-refuse beyond it,
DEPLOY_MODE=secret, confinement (traversal, absolute paths, symlink escape),
dual-use withholding, hardened headers, and that nothing but our own page is
ever served as HTML."""
import json
import urllib.error
import urllib.request
import zipfile
from io import BytesIO

import pytest

from security_council import serve
from security_council.orchestrator import run_scan
from tests.test_orchestrator import DEFAULT_CONFIG, FakeArm, _finding as orch_finding


def _target(tmp_path, runs=1):
    target = tmp_path / "repo"
    (target / "app").mkdir(parents=True)
    (target / "app" / "x.py").write_text("q = 1\n")
    cfg = DEFAULT_CONFIG | {"decisions": {"require_signatures": "warn", "signing_key": None}}
    out = []
    for i in range(runs):
        f = orch_finding(source_id="semgrep", kind="scanner", vendor="semgrep", rc=f"s{i}")
        out.append(run_scan(target, [FakeArm("semgrep", "scanner", "semgrep", [f])], cfg,
                            isolate=False))
    return target, out


def _get(url, token_cookie=None, method="GET"):
    req = urllib.request.Request(url, method=method)
    if token_cookie:
        req.add_header("Cookie", f"{serve.COOKIE}={token_cookie}")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


@pytest.fixture()
def viewer(tmp_path):
    target, runs = _target(tmp_path, runs=2)
    srv = serve.ReportServer(target, port=0)
    base = srv.start()
    yield srv, base, target, runs
    srv.stop()


# --------------------------------------------------------------------- #
# exposure policy
# --------------------------------------------------------------------- #

def test_loopback_needs_no_token_lan_needs_one(monkeypatch):
    assert serve.is_loopback("127.0.0.1") and serve.is_loopback("::1") and serve.is_loopback("localhost")
    assert not serve.is_loopback("0.0.0.0") and not serve.is_loopback("192.168.1.10")
    serve.check_bind("127.0.0.1", None)                       # fine
    with pytest.raises(serve.ServeRefused, match="token is required"):
        serve.check_bind("0.0.0.0", None)
    with pytest.raises(serve.ServeRefused, match="token is required"):
        serve.check_bind("192.168.1.10", "")
    serve.check_bind("0.0.0.0", "s3cret")                     # fine with a token
    monkeypatch.setenv("DEPLOY_MODE", "secret")
    with pytest.raises(serve.ServeRefused, match="DEPLOY_MODE=secret"):
        serve.check_bind("0.0.0.0", "s3cret")
    serve.check_bind("127.0.0.1", None)                       # loopback still fine


def test_auto_token_is_generated_and_required(tmp_path):
    target, _ = _target(tmp_path)
    srv = serve.ReportServer(target, port=0, token="auto")   # loopback + token: allowed
    base = srv.start()
    try:
        assert srv.token and len(srv.token) >= 24 and "?token=" in base
        root = base.split("?")[0]
        status, _, body = _get(root)
        assert status == 401 and b"requires its token" in body
        status, _, _ = _get(root + "?token=wrong")
        assert status == 401
        status, headers, _ = _get(base)                       # query token -> cookie
        assert status == 200 and serve.COOKIE in headers.get("Set-Cookie", "")
        assert "HttpOnly" in headers["Set-Cookie"] and "SameSite=Strict" in headers["Set-Cookie"]
        status, _, _ = _get(root, token_cookie=srv.token)     # cookie alone works
        assert status == 200
    finally:
        srv.stop()


# --------------------------------------------------------------------- #
# routes, confinement, dual-use, headers
# --------------------------------------------------------------------- #

def test_index_run_page_files_latest_and_zip(viewer):
    srv, base, target, runs = viewer
    status, headers, body = _get(base)
    assert status == 200 and headers["Content-Type"].startswith("text/html")
    for r in runs:
        assert f"/runs/{r.run_id}/".encode() in body
    assert b"loopback only" in body
    newest = runs[-1]
    status, headers, body = _get(base + f"runs/{newest.run_id}/")
    assert status == 200 and b"<h1>security-council report" in body
    status, headers, body = _get(base + f"runs/{newest.run_id}/summary.md")
    assert status == 200 and headers["Content-Type"].startswith("text/markdown")
    status, headers, body = _get(base + f"runs/{newest.run_id}/findings.json")
    assert status == 200 and headers["Content-Type"] == "application/json"
    assert json.loads(body)[0]["id"]
    status, headers, body = _get(base + f"runs/{newest.run_id}/merged.sarif")
    assert status == 200 and headers["Content-Type"] == "application/json"
    status, headers, _ = _get(base + "runs/latest/summary.md")
    assert status == 200                                       # followed the redirect
    status, headers, body = _get(base + f"runs/{newest.run_id}.zip")
    assert status == 200 and headers["Content-Type"] == "application/zip"
    names = zipfile.ZipFile(BytesIO(body)).namelist()
    assert f"{newest.run_id}/summary.md" in names and f"{newest.run_id}/manifest.json" in names
    # HEAD works and carries the same headers, no body
    status, headers, body = _get(base + f"runs/{newest.run_id}/", method="HEAD")
    assert status == 200 and body == b""
    for h, v in (("X-Content-Type-Options", "nosniff"), ("Referrer-Policy", "no-referrer"),
                 ("Cache-Control", "no-store")):
        assert headers[h] == v
    assert "default-src 'none'" in headers["Content-Security-Policy"]


def test_confinement_traversal_absolute_and_symlink_escape(viewer, tmp_path):
    srv, base, target, runs = viewer
    run = runs[-1]
    secret = tmp_path / "outside.txt"
    secret.write_text("SECRET")
    # a symlink INSIDE the run pointing outside must not be followed out
    (run.out_dir / "leak.txt").symlink_to(secret)
    (run.out_dir / "leakdir").symlink_to(tmp_path)
    for path in (f"runs/{run.run_id}/../../decisions/", f"runs/{run.run_id}/../../../outside.txt",
                 f"runs/{run.run_id}/leak.txt", f"runs/{run.run_id}/leakdir/outside.txt",
                 "runs/../repo/app/x.py", f"runs/{run.run_id}/%2e%2e/%2e%2e/outside.txt",
                 "runs//etc/passwd", "runs/latest/../../../outside.txt"):
        status, _, body = _get(base + path)
        assert status in (404, 403), path
        assert b"SECRET" not in body and b"q = 1" not in body, path
    # the store next to runs/ is not reachable at all
    (target / ".security-council" / "store.json").write_text("{}")
    (target / ".security-council" / "allowed_signers").write_text("alice ssh-ed25519 AAAA\n")
    for path in ("store.json", "allowed_signers", "runs/store.json", "runs/../store.json",
                 "runs/../allowed_signers", ".security-council/store.json"):
        status, _, body = _get(base + path)
        assert status == 404 and b"ssh-ed25519" not in body, path


def test_dual_use_artifacts_are_withheld_unless_asked(tmp_path):
    target, runs = _target(tmp_path)
    run = runs[0]
    d = run.out_dir / "raw" / "claude-analysis_attack-path"
    d.mkdir(parents=True)
    (d / "attack-path.md").write_text("# chains\n")
    (d / "document.json").write_text("{}")
    m = json.loads((run.out_dir / "manifest.json").read_text())
    m["artifacts"] = [{"kind": "attack-path", "producer": "house:claude", "dual_use": True,
                       "export_excluded": True,
                       "path": "raw/claude-analysis_attack-path/attack-path.md"}]
    (run.out_dir / "manifest.json").write_text(json.dumps(m))
    srv = serve.ReportServer(target, port=0)
    base = srv.start()
    try:
        for f in ("attack-path.md", "document.json"):
            status, _, body = _get(base + f"runs/{run.run_id}/raw/claude-analysis_attack-path/{f}")
            assert status == 403 and b"dual-use" in body
        status, _, body = _get(base + f"runs/{run.run_id}/raw/")
        assert status == 200 and b"(dual-use, not served)" in body and b"href=" not in body.split(b"claude-analysis_attack-path")[1][:40]
        _, _, z = _get(base + f"runs/{run.run_id}.zip")
        assert not any("attack-path" in n for n in zipfile.ZipFile(BytesIO(z)).namelist())
        # R14 own pass: a symlink ALIAS to the withheld directory (or a
        # case-insensitive filesystem) must not walk around the check
        (run.out_dir / "raw" / "alias").symlink_to(d)
        status, _, body = _get(base + f"runs/{run.run_id}/raw/alias/attack-path.md")
        assert status == 403 and b"dual-use" in body
        status, _, body = _get(base + f"runs/{run.run_id}/raw/")
        assert b"alias" in body and b"href='/runs/" + run.run_id.encode() + b"/raw/alias" not in body
        _, _, z = _get(base + f"runs/{run.run_id}.zip")
        assert not any("alias" in n or "attack-path" in n for n in zipfile.ZipFile(BytesIO(z)).namelist())
        (run.out_dir / "raw" / "alias").unlink()
    finally:
        srv.stop()
    srv = serve.ReportServer(target, port=0, include_dual_use=True)
    base = srv.start()
    try:
        status, _, body = _get(base + f"runs/{run.run_id}/raw/claude-analysis_attack-path/attack-path.md")
        assert status == 200 and body == b"# chains\n"
        _, _, z = _get(base + f"runs/{run.run_id}.zip")
        assert any("attack-path.md" in n for n in zipfile.ZipFile(BytesIO(z)).namelist())
    finally:
        srv.stop()


def test_summary_page_is_confined_too(viewer, tmp_path):
    """R14 (codex): the page path took a shortcut around _confine."""
    srv, base, target, runs = viewer
    run = runs[-1]
    secret = tmp_path / "outside.html"
    secret.write_text("<h1>SECRET</h1>")
    (run.out_dir / "summary.html").unlink()
    (run.out_dir / "summary.html").symlink_to(secret)
    status, _, body = _get(base + f"runs/{run.run_id}/")
    assert b"SECRET" not in body                      # rendered in memory instead, or 404
    assert status in (200, 404)


def test_viewer_never_writes_into_a_run(viewer):
    srv, base, target, runs = viewer
    run = runs[-1]
    (run.out_dir / "summary.html").unlink()
    before = sorted(p.name for p in run.out_dir.iterdir())
    status, headers, body = _get(base + f"runs/{run.run_id}/")
    assert status == 200 and b"<h1>security-council report" in body      # rendered in memory
    assert sorted(p.name for p in run.out_dir.iterdir()) == before     # nothing written


def test_only_our_summary_page_is_served_as_html(viewer):
    srv, base, target, runs = viewer
    run = runs[-1]
    (run.out_dir / "raw").mkdir(exist_ok=True)
    (run.out_dir / "raw" / "vendor.html").write_text("<script>alert(1)</script>")
    status, headers, body = _get(base + f"runs/{run.run_id}/raw/vendor.html")
    assert status == 200 and headers["Content-Type"].startswith("text/plain")
    assert headers["X-Content-Type-Options"] == "nosniff"
    status, _, _ = _get(base + f"runs/{run.run_id}/", method="POST")
    assert status in (501, 405)


def test_docs_are_rendered_with_links_and_confined(tmp_path):
    target, _ = _target(tmp_path)
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "README.md").write_text("# Docs\n\nSee [the guide](guide.md) and "
                                    "[evil](javascript:alert(1)) and <b>raw</b>.\n")
    (docs / "guide.md").write_text("# Guide\n\n- step `one`\n")
    (tmp_path / "private.md").write_text("PRIVATE")
    srv = serve.ReportServer(target, port=0, docs_root=docs)
    base = srv.start()
    try:
        status, headers, body = _get(base + "docs/")
        assert status == 200 and b'<a href="guide.md">the guide</a>' in body
        assert b'href="javascript' not in body and b"[evil](javascript:alert(1))" in body  # literal text
        assert b"<b>raw</b>" not in body and b"&lt;b&gt;raw" in body
        status, _, body = _get(base + "docs/guide.md")
        assert status == 200 and b"<h1" in body and b"<code>one</code>" in body
        status, _, body = _get(base + "docs/../private.md")
        assert status == 404 and b"PRIVATE" not in body
        _, _, index = _get(base)
        assert b"/docs/" in index
    finally:
        srv.stop()
    srv = serve.ReportServer(target, port=0, docs_root=None)
    srv.docs_root = None
    base = srv.start()
    try:
        assert _get(base + "docs/")[0] == 404
        assert b"/docs/" not in _get(base)[2]
    finally:
        srv.stop()


# --------------------------------------------------------------------- #
# CLI + MCP surfaces
# --------------------------------------------------------------------- #

def test_cli_serve_refuses_lan_without_token_and_prints_url(tmp_path, capsys, monkeypatch):
    target, _ = _target(tmp_path)
    from security_council import cli
    monkeypatch.setattr(cli, "cmd_serve", _once(cli.cmd_serve))
    rc = cli.main(["serve", "--target", str(target), "--port", "0"])
    out = capsys.readouterr().out
    assert rc == 0 and "security-council viewer: http://127.0.0.1:" in out and "loopback only" in out
    monkeypatch.setenv("DEPLOY_MODE", "secret")
    rc = cli.main(["serve", "--target", str(target), "--port", "0", "--bind", "0.0.0.0"])
    assert rc == 2 and "DEPLOY_MODE=secret" in capsys.readouterr().err
    monkeypatch.delenv("DEPLOY_MODE")
    # exposing without --token auto-generates one and says so loudly
    rc = cli.main(["serve", "--target", str(target), "--port", "0", "--bind", "0.0.0.0"])
    out = capsys.readouterr().out
    assert rc == 0 and "?token=" in out and "LAN-exposed" in out and "anyone with the token" in out


def _once(fn):
    def wrapper(args):
        args._once = True
        return fn(args)
    return wrapper


def test_mcp_serve_start_status_stop(tmp_path, monkeypatch):
    from security_council import mcp_server as srv_mod
    target, _ = _target(tmp_path)
    monkeypatch.setenv(srv_mod.ROOT_ENV, str(target))
    srv_mod._SERVER.clear()
    assert srv_mod.sc_serve({"action": "status"}) == {"running": False}
    monkeypatch.setenv("DEPLOY_MODE", "secret")
    with pytest.raises(ValueError, match="DEPLOY_MODE=secret"):
        srv_mod.sc_serve({"action": "start", "bind": "0.0.0.0", "port": 0})
    monkeypatch.delenv("DEPLOY_MODE")
    out = srv_mod.sc_serve({"action": "start", "port": 0})
    try:
        assert out["running"] and out["url"].startswith("http://127.0.0.1:") and out["exposure"] == "loopback only"
        assert srv_mod.sc_serve({"action": "status"})["running"] is True
        assert _get(out["url"])[0] == 200
        again = srv_mod.sc_serve({"action": "start", "port": 0})
        assert "already running" in again["note"]
    finally:
        assert srv_mod.sc_serve({"action": "stop"})["stopped"] is True
    assert srv_mod.sc_serve({"action": "status"}) == {"running": False}


# --------------------------------------------------------------------- #
# R14a (claude + antigravity): Host, "", confined root reads, stored HTML,
# content types, root-level dual-use, fail-closed manifest, zip cap, logs
# --------------------------------------------------------------------- #

def _get_host(url, host):
    req = urllib.request.Request(url)
    req.add_header("Host", host)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


def test_host_header_must_be_localhost_or_an_ip_literal(viewer):
    """S1 — DNS rebinding: a name that resolves to us is refused."""
    srv, base, target, runs = viewer
    assert serve.host_ok("localhost") and serve.host_ok("LOCALHOST:8642")
    assert serve.host_ok("127.0.0.1") and serve.host_ok("127.0.0.1:8642")
    assert serve.host_ok("192.168.1.5:80") and serve.host_ok("[::1]:8642") and serve.host_ok("[::1]")
    for bad in ("attacker.example", "attacker.example:8642", "localhost.evil", "", None,
                "127.0.0.1:abc", "[::1", "a b", "127.0.0.1.nip.io"):
        assert not serve.host_ok(bad), bad
    assert _get_host(base, "attacker.example:8642") == 421
    assert _get_host(base, "localhost") == 200
    assert _get_host(base, f"127.0.0.1:{srv.port}") == 200


def test_empty_bind_is_all_interfaces_not_loopback():
    """S2 — `""` binds INADDR_ANY; it must be treated like 0.0.0.0."""
    assert not serve.is_loopback("") and serve.needs_token("")
    with pytest.raises(serve.ServeRefused, match="token is required"):
        serve.check_bind("", None)


def test_run_root_reads_are_confined_and_stored_html_is_never_served(viewer, tmp_path):
    """S3/S5 — symlinked manifest/summary.md are not followed; a stored
    summary.html (ours or a hostile one) is never served as HTML."""
    srv, base, target, runs = viewer
    run = runs[-1]
    outside = tmp_path / "outside.json"
    outside.write_text(json.dumps({"run_id": "LEAK", "counts": {}, "arms": [], "exit_code": 0}))
    (run.out_dir / "manifest.json").rename(run.out_dir / "manifest.real")
    (run.out_dir / "manifest.json").symlink_to(outside)
    status, _, body = _get(base + f"runs/{run.run_id}/")
    assert b"LEAK" not in body and status in (200, 404)
    _, _, index = _get(base)
    assert b"LEAK" not in index
    (run.out_dir / "manifest.json").unlink()
    (run.out_dir / "manifest.real").rename(run.out_dir / "manifest.json")
    # a hostile stored summary.html is never what /runs/<id>/ returns
    (run.out_dir / "summary.html").write_text("<script>alert('planted')</script>")
    status, headers, body = _get(base + f"runs/{run.run_id}/")
    assert status == 200 and b"planted" not in body and b"<h1>security-council report" in body
    status, headers, body = _get(base + f"runs/{run.run_id}/summary.html")
    assert status == 200 and headers["Content-Type"].startswith("text/plain")


def test_document_types_are_text_or_downloads(viewer):
    srv, base, target, runs = viewer
    run = runs[-1]
    (run.out_dir / "raw" / "v").mkdir(parents=True, exist_ok=True)
    for name, content in (("summary.html", "<b>x</b>"), ("a.xhtml", "<x/>"), ("a.svg", "<svg/>"),
                          ("a.xml", "<a/>"), ("a.htm", "<p>")):
        (run.out_dir / "raw" / "v" / name).write_text(content)
        status, headers, _ = _get(base + f"runs/{run.run_id}/raw/v/{name}")
        assert status == 200 and headers["Content-Type"].startswith("text/plain"), name
    (run.out_dir / "raw" / "v" / "blob.bin").write_bytes(b"\x00\x01")
    status, headers, _ = _get(base + f"runs/{run.run_id}/raw/v/blob.bin")
    assert status == 200 and headers["Content-Type"] == "application/octet-stream"
    assert "attachment" in headers["Content-Disposition"]


def test_root_level_dual_use_and_unreadable_manifest_fail_closed(tmp_path):
    target, runs = _target(tmp_path)
    run = runs[0]
    (run.out_dir / "writeup.md").write_text("# w\n")
    (run.out_dir / "raw" / "x").mkdir(parents=True)
    (run.out_dir / "raw" / "x" / "log.txt").write_text("l")
    m = json.loads((run.out_dir / "manifest.json").read_text())
    m["artifacts"] = [{"kind": "writeup", "producer": "house:claude", "dual_use": True,
                       "export_excluded": True, "path": "writeup.md"}]
    (run.out_dir / "manifest.json").write_text(json.dumps(m))
    srv = serve.ReportServer(target, port=0)
    base = srv.start()
    try:
        assert _get(base + f"runs/{run.run_id}/writeup.md")[0] == 403      # antigravity: root-level
        assert _get(base + f"runs/{run.run_id}/summary.md")[0] == 200      # siblings unaffected
        assert _get(base + f"runs/{run.run_id}/raw/x/log.txt")[0] == 200
        (run.out_dir / "manifest.json").write_text("{not json")
        assert _get(base + f"runs/{run.run_id}/raw/x/log.txt")[0] == 403  # fail closed on raw/
        assert _get(base + f"runs/{run.run_id}/summary.md")[0] == 200
        assert _get(base + f"runs/{run.run_id}/")[0] == 404                # no manifest, no page
    finally:
        srv.stop()


def test_zip_size_cap_and_log_redaction(viewer, monkeypatch, capsys):
    srv, base, target, runs = viewer
    run = runs[-1]
    monkeypatch.setattr(serve, "ZIP_MAX_BYTES", 10)
    status, _, body = _get(base + f"runs/{run.run_id}.zip")
    assert status == 413 and b"download its files individually" in body
    monkeypatch.setenv("SECURITY_COUNCIL_SERVE_LOG", "1")

    class _H(serve._Handler):
        def __init__(self):
            self.client_address = ("127.0.0.1", 1)
            self.requestline = "GET /?token=SECRETTOKEN HTTP/1.1"
        def address_string(self):
            return "127.0.0.1"
        def log_date_time_string(self):
            return "now"
    _H().log_message('"%s" %s %s', "GET /?token=SECRETTOKEN HTTP/1.1", "200", "-")
    err = capsys.readouterr().err
    assert "SECRETTOKEN" not in err and "token=REDACTED" in err


def test_safe_href_and_docs_root_guard(tmp_path):
    from security_council.export import mdrender
    for bad in ("mailto:x@y", "file:/etc/passwd", "ftp://x", "javascript:alert(1)", "data:x",
                "//evil", "\\\\host\\x", "JAVASCRIPT:x", "custom+scheme:y"):
        assert mdrender._safe_href(bad) is None, bad
    for ok in ("guide.md", "../other.md", "http://example.org/x", "HTTPS://example.org", "#anchor", "a:b/c"):
        assert mdrender._safe_href(ok) == ok or ok == "a:b/c", ok
    assert mdrender._safe_href("a:b/c") is None                      # scheme-shaped: text
    assert serve._default_docs_root() is not None                    # this IS the checkout
