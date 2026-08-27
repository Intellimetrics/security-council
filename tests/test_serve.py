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
