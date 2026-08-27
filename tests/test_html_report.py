"""summary.html: the dashboard + the markdown body rendered by mdrender.

The page must (1) carry every section of summary.md — heading for heading —
so it can never lag the markdown again, (2) keep the R8 hardening: one
escaping boundary, zero script, zero external assets, and (3) be produced by
every scan next to summary.md, with `runs/latest` pointing at the newest run
and `runs` / `report` / `--open` able to find it."""
import json
import re
from html import unescape

import pytest

from security_council.cli import main as cli_main
from security_council.export import html_export, markdown, mdrender
from security_council.orchestrator import run_scan
from tests.test_cluster import mk
from tests.test_export_formats import MANIFEST, _suppressed
from tests.test_orchestrator import FakeArm, _finding as orch_finding

# --------------------------------------------------------------------- #
# mdrender: the dialect, and nothing but the dialect
# --------------------------------------------------------------------- #


def test_inline_escapes_win_over_markers_and_text_is_html_escaped():
    assert mdrender.inline(r"a \*not bold\* \`not code\` \<b\>") == "a *not bold* `not code` &lt;b&gt;"
    assert mdrender.inline("**HIGH** x") == '<strong class="sev high">HIGH</strong> x'
    assert mdrender.inline("**bold** and `code_with_underscores`") == \
        "<strong>bold</strong> and <code>code_with_underscores</code>"
    assert mdrender.inline("_italic text_") == "<em>italic text</em>"
    assert mdrender.inline("state needs_human is not italic") == "state needs_human is not italic"
    assert mdrender.inline('<script>alert(1)</script> & "q"') == \
        "&lt;script&gt;alert(1)&lt;/script&gt; &amp; &quot;q&quot;"
    assert mdrender.inline("dangling ** and ` stay literal") == "dangling ** and ` stay literal"


def test_blocks_headings_lists_tables_fences_quotes():
    md = "\n".join([
        "# Title", "", "## Section A", "- one", "  - nested `c`", "- two", "",
        "| H1 | H2 |", "|---|---|", "| a \\| b | **HIGH** |", "",
        "> a note", "> continued", "",
        "````python", "x = '```'", "````", "",
        "para line one", "para line two", "", "### Sub",
    ])
    body, heads = mdrender.render(md)
    assert [(lvl, txt) for lvl, _, txt in heads] == [(1, "Title"), (2, "Section A"), (3, "Sub")]
    assert '<h2 id="section-a">Section A</h2>' in body
    assert "<ul><li>one<ul><li>nested <code>c</code></li></ul></li><li>two</li></ul>" in body
    assert "<th>H1</th>" in body and "<td>a | b</td>" in body
    assert '<td><strong class="sev high">HIGH</strong></td>' in body
    assert "<blockquote><p>a note continued</p></blockquote>" in body
    assert "<pre><code class=\"lang-python\">x = &#x27;```&#x27;</code></pre>" in body
    assert "<p>para line one para line two</p>" in body


def test_render_never_emits_a_tag_from_content():
    hostile = ('# <img src=x onerror=alert(1)>\n\n| <b>x</b> | y |\n|---|---|\n| <a href="j">z</a> | q |\n\n'
               '```\n</code></pre><script>alert(2)</script>\n```\n')
    body, _ = mdrender.render(hostile)
    for bad in ("<img", "<b>", "<a ", "<script", "</pre><script"):
        assert bad not in body, bad
    assert "&lt;img src=x onerror=alert(1)&gt;" in body


# --------------------------------------------------------------------- #
# the page: parity with summary.md, hardening, dashboard
# --------------------------------------------------------------------- #

def _page(findings, manifest, **kw):
    return html_export.to_html(findings, manifest, **kw)


def _md_headings(md: str) -> list[str]:
    return [mdrender.inline(m.group(1)) for m in re.finditer(r"^#{2,3} (.*)$", md, re.M)]


def test_page_carries_every_markdown_section_heading_for_heading():
    """Drift-proof by construction: the page body IS the markdown."""
    a = mk(path="app/x.py", cwe="CWE-89", family="injection", source_id="semgrep",
           source_kind="scanner", vendor="semgrep")
    a.title = "SQL built from request <input> & friends"
    b = _suppressed(mk(path="app/y.py", cwe="CWE-79", family="xss", source_id="semgrep",
                       source_kind="scanner", vendor="semgrep"))
    mf = dict(MANIFEST, signature_policy={"configured": "enforce", "effective": "enforce",
                                          "reason": "set by config", "verifier": "OpenSSH"},
              prior_decisions=[{"finding_id": b.id, "action": "reapplied_suppressed",
                                "ref": "decision:root_cause:x", "title": b.title,
                                "severity": "high", "operator": "alice@example",
                                "decided_at": "2026-08-01T00:00:00Z",
                                "expires_at": "2026-10-30T00:00:00Z", "signature": "verified",
                                "reapplied_count": 2, "high_assurance": False}],
              degradations=[{"kind": "partial_coverage", "arm": "semgrep",
                             "detail": "the repository's own ignore rules were in effect"}],
              artifacts=[{"id": "A1", "kind": "threat-model", "producer": "house:claude",
                          "path": "raw/claude-analysis_threat-model/threat-model.md",
                          "format": "markdown", "model_id": "claude-fable-5",
                          "export_excluded": False, "dual_use": False, "title": "TM"}])
    md = markdown.to_markdown([a, b], mf)
    page = _page([a, b], mf, markdown_text=md)
    for h in _md_headings(md):
        assert h in page, h
    # and the body is the markdown: a phrase that exists only in the markdown appears once there
    assert "Suppressions reapplied from the decision store" in page
    assert "Decision signatures" in page and "Analysis artifacts" in page
    assert page.count("<h2") == md.count("\n## ") + 2      # md h2s + Degradations + Where to look
    # the metadata bullets before the first section are not repeated in the body
    assert "<strong>Target:</strong>" not in page and "<strong>Policy:</strong>" not in page
    assert page.count("security-council report — run") == 1


def test_page_is_hardened_and_self_contained():
    hostile = mk(path="app/x.py", cwe="CWE-89", family="injection", source_id="semgrep",
                 source_kind="scanner", vendor="semgrep")
    hostile.title = '<script>alert(1)</script><img src=x onerror=alert(2)>'
    hostile.description = "see http://evil.example/x and <iframe src=y>"
    mf = dict(MANIFEST, target={"root": "/tmp/<b>repo</b>", "git_commit": "abc<def>"},
              degradations=[{"kind": "arm_failed", "arm": "x<y>", "detail": "<script>"}])
    page = _page([hostile], mf)
    assert "<script" not in page and "<img" not in page and "<iframe" not in page
    assert "&lt;script&gt;" in page
    assert "http://" not in page and "https://" not in page and "javascript" not in page.lower()
    assert "src=" not in page.replace("src=x", "").replace("src=y", "")
    assert "<link" not in page and "@import" not in page and "url(" not in page
    # opened from disk there are no response headers: the page carries its own CSP
    assert "http-equiv='Content-Security-Policy'" in page and "default-src 'none'" in page


def test_dashboard_gate_tiles_next_steps_and_where_to_look(tmp_path):
    a = mk(path="app/x.py", cwe="CWE-89", family="injection", source_id="semgrep",
           source_kind="scanner", vendor="semgrep")
    mf = dict(MANIFEST, exit_code=1, counts={"total": 1, "by_severity": {"high": 1},
                                             "by_state": {"new": 1}},
              policy={"fail_on_severity": "high", "gate_baseline": "all"},
              arms=[{"name": "semgrep", "kind": "scanner", "ok": True, "raw_results": 1,
                     "normalized": 1, "elapsed_seconds": 1.0},
                    {"name": "gitleaks", "kind": "scanner", "ok": False, "error": "boom"}],
              degradations=[{"kind": "arm_failed", "arm": "gitleaks", "detail": "boom"}],
              artifacts=[{"kind": "attack-path", "producer": "house:claude",
                          "path": "raw/claude-analysis_attack-path/attack-path.md",
                          "export_excluded": True, "dual_use": True}],
              verify_fix={"method": "deterministic", "patches": [{"patch": "fix.patch"}]})
    (tmp_path / "raw" / "semgrep").mkdir(parents=True)
    (tmp_path / "exports").mkdir()
    page = _page([a], mf, run_dir=tmp_path)
    assert 'class="gate fail">GATE: FAIL' in page and "(exit 1)" in page
    assert "policy: fail on ≥ <code>high</code>" in page and "config: defaults" in page
    repo_cfg = _page([a], dict(mf, config_source={"kind": "repository", "path": "/r/.security-council.yaml"}))
    assert "loaded from the scanned repository" in repo_cfg and "/r/.security-council.yaml" in repo_cfg
    assert "1 finding(s) fail the gate" in page and "1 high" in page
    assert "security-council suppress" in page and "baseline set" in page
    assert '<div class="k">gating</div><div class="v">1</div>' in page
    assert "failed: gitleaks" in page
    assert "Degradations — why this run is not a clean bill" in page and "boom" in page
    for link in ("summary.md", "merged.sarif", "findings.json", "manifest.json", "policy.json",
                 "raw/semgrep/", "raw/claude-analysis_attack-path/attack-path.md",
                 "verify-patch/", "exports/"):
        assert f'href="{link}"' in page, link
    assert "dual-use: kept out of shareable exports" in page
    clean = _page([], dict(MANIFEST, exit_code=0, counts={"total": 0, "by_severity": {},
                                                          "by_state": {}}, degradations=[]))
    assert 'class="gate pass">GATE: PASS' in clean and "No open finding at or above" in clean
    degraded = _page([], dict(MANIFEST, exit_code=3, counts={"total": 0, "by_severity": {},
                                                             "by_state": {}},
                              degradations=[{"kind": "no_arms_succeeded", "detail": "x"}]))
    assert "DEGRADED" in degraded and "NOT a clean bill" in degraded


def test_manifest_paths_are_linked_only_when_they_are_relative_run_paths():
    """R14 (codex): an artifact path from a (tamperable) manifest was escaped
    as text but still became an href — active in a file:// report."""
    a = mk(path="app/x.py", cwe="CWE-89", family="injection", source_id="semgrep",
           source_kind="scanner", vendor="semgrep")
    bad = ["http://evil.example/x", "javascript:alert(1)", "//evil.example/x",
           "/etc/passwd", "../../outside.md", "raw/../../x", "C:\\x", "data:text/html,hi"]
    mf = dict(MANIFEST, artifacts=[{"kind": "threat-model", "producer": "house:claude",
                                    "path": p, "export_excluded": False} for p in bad]
              + [{"kind": "threat-model", "producer": "house:claude",
                  "path": "raw/claude-analysis_threat-model/threat-model.md",
                  "export_excluded": False}])
    page = _page([a], mf)
    for p in bad:
        assert f'href="{html_export._e(p)}"' not in page, p
    assert 'href="raw/claude-analysis_threat-model/threat-model.md"' in page
    assert page.count("not linked: not a path in this run") == len(bad)
    assert "http://" not in page.replace("http://evil.example/x", "")  # only as escaped text
    for p in bad:
        assert html_export._safe_rel(p) is None, p
    assert html_export._safe_rel("raw/x/y.md") == "raw/x/y.md"
    assert html_export._safe_rel("raw/%2e%2e/x") is None            # R14 HX-1


def test_existing_r8_expectations_still_hold():
    f = mk(path="src/A.java", cwe="CWE-79", family="xss", source_id="semgrep",
           source_kind="scanner", vendor="semgrep")
    scores = {f.id: {"p": 0.6538, "measured_p": 0.6538, "clamps": [],
                     "record": "owasp-benchmark-java-1.2@2026-08-24"}}
    mf = dict(MANIFEST, calibration={"status": "active", "applied_findings": 1,
                                     "record": "owasp-benchmark-java-1.2@2026-08-24"})
    page = _page([f], mf, scores=scores)
    assert "0.65" in page and "fitted" in page and "calibrat" not in page.lower()


# --------------------------------------------------------------------- #
# every scan writes it; latest; runs; report; --open
# --------------------------------------------------------------------- #

def _scan(tmp_path, rc="html"):
    arms = [FakeArm("semgrep", "scanner", "semgrep",
                    [orch_finding(source_id="semgrep", kind="scanner", vendor="semgrep", rc=rc)])]
    cfg_target = tmp_path
    return run_scan(cfg_target, arms, __import__("tests.test_orchestrator", fromlist=["_run"])
                    .DEFAULT_CONFIG | {"decisions": {"require_signatures": "warn", "signing_key": None}},
                    isolate=False)


def test_scan_writes_summary_html_and_points_latest(tmp_path):
    target = tmp_path / "repo"
    (target / "app").mkdir(parents=True)
    (target / "app" / "x.py").write_text("q = 1\n")
    run = _scan(target)
    page = run.out_dir / "summary.html"
    assert page.is_file() and "<h1>security-council report" in page.read_text()
    assert any(r["format"] == "html" and r["path"].endswith("summary.html")
               for r in run.manifest["reports"])
    latest = run.out_dir.parent / "latest"
    assert latest.is_symlink() and latest.resolve() == run.out_dir.resolve()
    md = (run.out_dir / "summary.md").read_text()
    for h in _md_headings(md):
        assert h in page.read_text(), h
    # FakeArm writes no raw/ dir, so the page falls back to the generic link;
    # a real arm's directory is linked by name (covered in the dashboard test)
    assert 'href="raw/"' in page.read_text()
    run2 = _scan(target, rc="second")
    assert (run.out_dir.parent / "latest").resolve() == run2.out_dir.resolve()


def test_runs_report_latest_and_open(tmp_path, capsys, monkeypatch):
    target = tmp_path / "repo"
    (target / "app").mkdir(parents=True)
    (target / "app" / "x.py").write_text("q = 1\n")
    run = _scan(target)
    t = ["--target", str(target)]
    assert cli_main(["runs", *t]) == 0
    out = capsys.readouterr().out
    assert run.run_id in out and "exit 1" in out and "arms=semgrep" in out and "latest ->" in out
    assert cli_main(["runs", "--json", *t]) == 0
    rows = json.loads(capsys.readouterr().out)
    assert rows[0]["run_id"] == run.run_id and rows[0]["summary_html"].endswith("summary.html")
    # report with no run dir = the latest run
    assert cli_main(["report", *t]) == 0
    assert json.loads(capsys.readouterr().out)["run_id"] == run.run_id
    assert cli_main(["report", "--format", "html", *t]) == 0
    assert "<h1>security-council report" in capsys.readouterr().out
    # --open re-renders summary.html and hands it to the browser (stubbed)
    opened = []
    monkeypatch.setattr("webbrowser.open", lambda url: opened.append(url) or True)
    (run.out_dir / "summary.html").unlink()
    assert cli_main(["report", "--open", *t]) == 0
    assert opened and opened[0].startswith("file://") and opened[0].endswith("summary.html")
    assert (run.out_dir / "summary.html").is_file()
    assert "report:" in capsys.readouterr().out
    # a stray `latest` symlink is never mistaken for a run
    assert (target / ".security-council" / "runs" / "latest").is_symlink()
    from security_council.cli import run_dirs
    assert [d.name for d in run_dirs(target)] == [run.run_id]
    # nothing to report on an empty target
    empty = tmp_path / "empty"
    empty.mkdir()
    assert cli_main(["report", "--target", str(empty)]) == 2
    assert cli_main(["runs", "--target", str(empty)]) == 1


def test_scan_open_flag(tmp_path, monkeypatch, capsys):
    from security_council import cli
    target = tmp_path / "repo"
    (target / "app").mkdir(parents=True)
    (target / "app" / "x.py").write_text("q = 1\n")
    (target / ".security-council.yaml").write_text("decisions:\n  require_signatures: warn\n")
    opened = []
    monkeypatch.setattr("webbrowser.open", lambda url: opened.append(url) or True)
    monkeypatch.setattr(cli, "_build_arms", lambda names, config=None, diff=None: [
        FakeArm("semgrep", "scanner", "semgrep",
                [orch_finding(source_id="semgrep", kind="scanner", vendor="semgrep", rc="o")])])
    rc = cli.main(["scan", str(target), "--arms", "semgrep", "--inplace", "--open", "--json"])
    assert rc == 1
    assert opened and unescape(opened[0]).endswith("summary.html")


@pytest.mark.parametrize("md", ["", "# only a title\n", "just a paragraph"])
def test_render_degenerate_inputs(md):
    body, heads = mdrender.render(md)
    assert "<script" not in body
