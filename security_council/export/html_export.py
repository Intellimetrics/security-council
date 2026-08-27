"""`summary.html` — the one-page report written on every scan (and
re-renderable with `report <run> --format html` / `report --open`).

Two parts. The DASHBOARD at the top is computed from the finding model and
the manifest: gate banner, what-to-do-next, tiles (severity, state, arms,
corroboration, demoted, degradations, decision signatures), the degradation
box, and a "Where to look" block that links every file the run produced —
`summary.md`, SARIF, `findings.json`, the raw per-arm bundles, analysis
documents, patch verification. The BODY is `summary.md` itself, rendered by
`mdrender` — the markdown is the system of record and the page cannot lag
it (`tests/test_html_report.py` pins heading-for-heading parity).

Security posture (kept from the R8 exporter): ONE hardened escaping
boundary — every dynamic value passes through `html.escape` (`_e` here,
`mdrender.e` in the body) — zero script, zero external assets (inline CSS,
no fonts, no images; the only links are relative paths inside the run
directory), so the file is safe to open from an untrusted run directory and
works air-gapped. Print = PDF.
"""

from __future__ import annotations

import html
from pathlib import Path

from .. import policy as _policy
from ..model import Finding
from . import markdown as _markdown
from . import mdrender

_SEV_ORDER = ("critical", "high", "medium", "low", "info")
_STATE_ORDER = ("validated", "likely", "new", "disputed", "needs_human", "refuted")
_SEV_RANK = {s: i for i, s in enumerate(_SEV_ORDER)}


def _e(v: object) -> str:
    """THE escaping boundary for the dashboard; the body uses mdrender.e."""
    return html.escape("" if v is None else str(v), quote=True)


_CSS = """
:root { --fg:#1a1f27; --bg:#ffffff; --mut:#5b6472; --line:#d8dde5; --card:#f5f7fa;
        --crit:#8f1d21; --high:#b3541e; --med:#8a6d1a; --low:#3a6ea5; --info:#5b6472;
        --ok:#2f7d4f; --warn:#8a6d1a; --failbg:#fbeaea; --okbg:#e8f4ec; --warnbg:#fff6df;
        --link:#1f5fbf; }
@media (prefers-color-scheme: dark) {
  :root { --fg:#e6e9ef; --bg:#12151a; --mut:#9aa4b2; --line:#2c3340; --card:#1b2028;
          --crit:#ff8a8f; --high:#ffab70; --med:#e6c46a; --low:#8ab8ff; --info:#9aa4b2;
          --ok:#7fd39a; --warn:#e6c46a; --failbg:#3a1d1f; --okbg:#173124; --warnbg:#3a3116;
          --link:#8ab8ff; }
}
* { box-sizing:border-box; }
body { margin:0; color:var(--fg); background:var(--bg);
       font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif; }
.page { max-width:74rem; margin:0 auto; padding:1.5rem 1rem 3rem; }
h1,h2,h3,h4 { line-height:1.25; } h1 { font-size:1.55rem; margin:.2rem 0 .6rem; }
h2 { font-size:1.25rem; margin-top:2.2rem; border-bottom:1px solid var(--line); padding-bottom:.25rem; }
h3 { font-size:1.05rem; margin-top:1.6rem; }
code { font-family:ui-monospace,Consolas,monospace; font-size:.92em;
       background:var(--card); padding:.1em .35em; border-radius:4px; }
pre { background:var(--card); border:1px solid var(--line); border-radius:8px;
      padding:.7rem .9rem; overflow-x:auto; }
pre code { background:none; padding:0; }
.tbl { overflow-x:auto; margin:.75rem 0; }
table { border-collapse:collapse; width:100%; }
th,td { border:1px solid var(--line); padding:.35rem .55rem; text-align:left;
        vertical-align:top; font-size:.92rem; }
th { background:var(--card); }
blockquote { margin:.8rem 0; padding:.5rem .9rem; border-left:4px solid var(--warn);
             background:var(--warnbg); }
a { color:var(--link); }
.meta { color:var(--mut); font-size:.9rem; margin:0 0 .8rem; }
.gate { padding:.8rem 1rem; border-radius:10px; font-weight:700; font-size:1.05rem; margin:.8rem 0; }
.gate.fail { background:var(--failbg); color:var(--crit); border:1px solid var(--crit); }
.gate.pass { background:var(--okbg); color:var(--ok); border:1px solid var(--ok); }
.gate.warn { background:var(--warnbg); color:var(--warn); border:1px solid var(--warn); }
.next { margin:.4rem 0 1.2rem; padding:.7rem 1rem; background:var(--card);
        border:1px solid var(--line); border-radius:10px; }
.tiles { display:grid; grid-template-columns:repeat(auto-fit,minmax(9.5rem,1fr)); gap:.6rem; margin:1rem 0; }
.tile { background:var(--card); border:1px solid var(--line); border-radius:10px; padding:.6rem .8rem; }
.tile .k { color:var(--mut); font-size:.78rem; text-transform:uppercase; letter-spacing:.04em; }
.tile .v { font-size:1.5rem; font-weight:700; line-height:1.2; }
.tile .s { color:var(--mut); font-size:.82rem; }
.sev { font-weight:700; text-transform:uppercase; font-size:.82em; }
.sev.critical { color:var(--crit); } .sev.high { color:var(--high); }
.sev.medium { color:var(--med); } .sev.low { color:var(--low); } .sev.info { color:var(--info); }
.box { border-radius:10px; padding:.7rem 1rem; margin:1rem 0; border:1px solid var(--line); }
.box.degr { background:var(--failbg); border-color:var(--crit); }
.box.degr h2 { margin-top:0; border:0; color:var(--crit); font-size:1.05rem; }
.box.look { background:var(--card); }
.box.look h2 { margin-top:0; border:0; font-size:1.05rem; }
.box ul { margin:.3rem 0 0 1.1rem; padding:0; }
nav.toc { font-size:.9rem; color:var(--mut); margin:.6rem 0 1.4rem; }
nav.toc a { margin-right:.9rem; white-space:nowrap; }
main ul { padding-left:1.3rem; } main li { margin:.15rem 0; }
footer { margin:2.5rem 0 1rem; color:var(--mut); font-size:.85rem;
         border-top:1px solid var(--line); padding-top:.8rem; }
@media print { nav.toc { display:none; } .page { max-width:none; padding:0; }
               pre { white-space:pre-wrap; } h2 { break-after:avoid; } }
"""

_EXIT = {
    0: ("pass", "PASS — no gating findings"),
    1: ("fail", "FAIL — gating findings present"),
    2: ("warn", "USAGE ERROR"),
    3: ("warn", "DEGRADED — partial results; this is NOT a clean bill"),
    4: ("fail", "ENTITLEMENT REFUSED — an undeclared gated model tier was requested"),
    5: ("fail", "PREFLIGHT REFUSED"),
}


def _gating(findings: list[Finding], manifest: dict) -> list[Finding]:
    pol = manifest.get("policy") or {}
    threshold = _SEV_RANK.get(pol.get("fail_on_severity", "high"), 1)
    baseline_new = pol.get("gate_baseline") == "new"
    out = []
    for f in findings:
        d = f.disposition
        if d.lifecycle not in ("open", "reopened") or d.state == "refuted" or d.sarif_suppression:
            continue
        if _SEV_RANK.get(f.severity.label, 9) > threshold:
            continue
        if baseline_new and f.baseline_state in ("unchanged", "updated") \
                and not _policy.baseline_ineligible(f):
            continue
        out.append(f)
    return out


def _tile(k: str, v: object, s: str = "") -> str:
    return (f'<div class="tile"><div class="k">{_e(k)}</div><div class="v">{_e(v)}</div>'
            + (f'<div class="s">{_e(s)}</div>' if s else "") + "</div>")


def _next_steps(exit_code, gating: list[Finding], manifest: dict) -> str:
    pol = manifest.get("policy") or {}
    thr = pol.get("fail_on_severity", "high")
    degr = manifest.get("degradations") or []
    if exit_code == 0:
        msg = (f"No open finding at or above <code>{_e(thr)}</code>. Lower-severity findings, "
               "if any, are listed below and worth a look when convenient.")
    elif exit_code == 1:
        by = {}
        for f in gating:
            by[f.severity.label] = by.get(f.severity.label, 0) + 1
        parts = ", ".join(f"{n} {s}" for s, n in sorted(by.items(), key=lambda kv: _SEV_RANK.get(kv[0], 9)))
        msg = (f"<strong>{len(gating)} finding(s) fail the gate</strong> ({_e(parts)}; threshold "
               f"<code>{_e(thr)}</code>). For each: fix it and re-scan; or, if it is a false positive, "
               "<code>security-council suppress &lt;id&gt; --operator you --justification \"…\" "
               "--signing-key ~/.ssh/id_ed25519</code>; or adopt an existing backlog with "
               "<code>baseline set</code> + <code>--gate-baseline new</code> so only new findings gate.")
    elif exit_code == 3:
        msg = (f"<strong>Degraded run</strong> — {len(degr)} problem(s) listed in the red box below. "
               "A scanner failed, verified nothing, or covered only part of the tree, so a clean "
               "result here would not mean clean code. Fix the cause and re-scan.")
    else:
        msg = "The run did not complete normally — see the gate banner and the degradations."
    return f'<div class="next">{msg}</div>'


def _where_to_look(manifest: dict, run_dir: Path | None) -> str:
    rows: list[str] = []

    def link(rel: str, label: str, note: str = "") -> None:
        rows.append(f'<li><a href="{_e(rel)}"><code>{_e(rel)}</code></a> — {_e(label)}'
                    + (f' <span class="meta">{_e(note)}</span>' if note else "") + "</li>")

    link("summary.md", "this report as markdown (the system of record for the page)")
    link("merged.sarif", "SARIF 2.1.0 for GitHub/ADO/GitLab code scanning")
    link("findings.json", "the canonical finding model — every exporter renders from this")
    link("manifest.json", "what ran, on what, with what result; degradations; decisions applied")
    link("policy.json", "per-finding score terms, clamps and guardrails consulted")
    raw_dirs: list[str] = []
    if run_dir is not None and (run_dir / "raw").is_dir():
        raw_dirs = sorted(p.name for p in (run_dir / "raw").iterdir() if p.is_dir())
    if raw_dirs:
        for d in raw_dirs:
            link(f"raw/{d}/", "the arm's raw, unmerged output (vendor bundle, SARIF, logs)")
    else:
        link("raw/", "per-arm raw output")
    for a in manifest.get("artifacts") or []:
        p = a.get("path")
        if not p:
            continue
        kind = a.get("kind", "artifact")
        note = "dual-use: kept out of shareable exports" if a.get("export_excluded") else ""
        link(str(p), f"{kind} ({a.get('producer', '')})", note)
    vf = manifest.get("verify_fix") or {}
    if vf.get("patches"):
        link("verify-patch/", "patch verification: patched-copy scanner output")
    if run_dir is not None and (run_dir / "exports").is_dir():
        link("exports/", "report bundles (report --bundle triage|gov|all)")
    else:
        rows.append('<li><span class="meta">More formats: <code>security-council report '
                    '&lt;run&gt; --format html|csv|cklb|cyclonedx|emass|openvex|oscal-ar</code>, or '
                    '<code>--bundle triage|gov|all</code> → <code>exports/</code></span></li>')
    return '<div class="box look"><h2>Where to look</h2><ul>' + "".join(rows) + "</ul></div>"


def _dashboard(findings: list[Finding], manifest: dict, run_dir: Path | None) -> str:
    counts = manifest.get("counts") or {}
    sev = counts.get("by_severity") or {}
    state = counts.get("by_state") or {}
    arms = manifest.get("arms") or []
    ok = [a for a in arms if a.get("ok")]
    failed = [a for a in arms if not a.get("ok")]
    exit_code = manifest.get("exit_code")
    cls, label = _EXIT.get(exit_code, ("warn", f"exit {exit_code}"))
    gating = _gating(findings, manifest)
    demoted = [f for f in findings if _markdown._is_demoted(f)]
    corroborated = [f for f in findings
                    if (f.corroboration.independent_family_count
                        or len(set(f.corroboration.vendor_families))) >= 2]
    validated = [f for f in findings if f.validation is not None]
    degr = manifest.get("degradations") or []
    sp = manifest.get("signature_policy") or {}
    tgt = manifest.get("target") or {}
    src = manifest.get("config_source") or {}
    scope = (manifest.get("scan_scope") or {}).get("kind", "full")
    tool = (manifest.get("tool") or {}).get("security_council", "?")

    out = [f"<h1>security-council report — run <code>{_e(manifest.get('run_id'))}</code></h1>"]
    meta = [f"target <code>{_e(tgt.get('root'))}</code>"]
    if tgt.get("git_commit"):
        meta.append(f"commit <code>{_e(str(tgt.get('git_commit'))[:12])}</code>")
    meta.append(f"{_e(manifest.get('started_at'))} → {_e(manifest.get('finished_at'))}")
    meta.append(f"security-council {_e(tool)}")
    if scope != "full":
        meta.append(f"<strong>⚠ partial — {_e(scope)} scan</strong>")
    out.append(f'<p class="meta">{" · ".join(meta)}</p>')
    pol = manifest.get("policy") or {}
    line2 = [f"policy: fail on ≥ <code>{_e(pol.get('fail_on_severity', 'high'))}</code>"
             f" · min arms ok <code>{_e(pol.get('min_arms_ok', 1))}</code>"
             f" · auto-suppress {'on' if pol.get('auto_suppress') else 'off'}"
             + (" · gate only new vs baseline" if pol.get("gate_baseline") == "new" else "")]
    if src.get("kind") == "repository":
        line2.append(f"config <code>{_e(src.get('path'))}</code> — <strong>⚠ loaded from the "
                     "scanned repository</strong> (in CI pass <code>--ignore-repo-config</code>)")
    elif src.get("kind") == "explicit":
        line2.append(f"config <code>{_e(src.get('path'))}</code> (operator-supplied)")
    else:
        line2.append("config: defaults" + (f" ({_e(src.get('note'))})" if src.get("note") else ""))
    out.append(f'<p class="meta">{" · ".join(line2)}</p>')
    out.append(f'<div class="gate {cls}">GATE: {_e(label)} (exit {_e(exit_code)})</div>')
    out.append(_next_steps(exit_code, gating, manifest))

    tiles = [_tile("findings", counts.get("total", len(findings)), "root-cause clusters")]
    for s in _SEV_ORDER:
        if sev.get(s):
            tiles.append(f'<div class="tile"><div class="k">{_e(s)}</div>'
                         f'<div class="v sev {_e(s)}">{_e(sev[s])}</div></div>')
    tiles.append(_tile("gating", len(gating), f"at/above {(manifest.get('policy') or {}).get('fail_on_severity', 'high')}"))
    tiles.append(_tile("corroborated", len(corroborated), "≥2 independent vendor families"))
    tiles.append(_tile("validated", len(validated),
                       "cross-examined by the panel" if validated else "panel not run"))
    tiles.append(_tile("demoted", len(demoted), "left the gate, still listed"))
    tiles.append(_tile("arms", f"{len(ok)}/{len(arms)}", "completed" if not failed else
                       "failed: " + ", ".join(a.get("name", "?") for a in failed)))
    tiles.append(_tile("degradations", len(degr), "see below" if degr else "none"))
    if sp.get("effective") and sp.get("effective") != "off":
        tiles.append(_tile("signatures", sp["effective"], "decision-store policy"))
    if state:
        tiles.append(_tile("states", " · ".join(f"{k} {v}" for k, v in sorted(
            state.items(), key=lambda kv: _STATE_ORDER.index(kv[0]) if kv[0] in _STATE_ORDER else 9)), ""))
    out.append('<div class="tiles">' + "".join(tiles) + "</div>")

    if degr:
        items = "".join(f"<li><code>{_e(d.get('kind'))}</code>"
                        + (f" <code>{_e(d.get('arm'))}</code>" if d.get("arm") else "")
                        + f" — {_e(d.get('detail'))}</li>" for d in degr)
        out.append(f'<div class="box degr"><h2>Degradations — why this run is not a clean bill</h2>'
                   f"<ul>{items}</ul></div>")
    out.append(_where_to_look(manifest, run_dir))
    return "\n".join(out)


def to_html(findings: list[Finding], manifest: dict, *, scores: dict | None = None,
            run_dir: str | Path | None = None, markdown_text: str | None = None) -> str:
    """The whole page. ``markdown_text`` lets the orchestrator pass the exact
    `summary.md` it just wrote; otherwise it is regenerated from the same
    inputs. ``run_dir`` (when the run is on disk) makes "Where to look"
    link the real `raw/` bundles and `exports/`."""
    md = markdown_text if markdown_text is not None else _markdown.to_markdown(
        findings, manifest, scores=scores)
    # the dashboard already carries the title and the metadata bullets
    # (target, config source, run window, policy, gate) — the body starts at
    # the first section
    if md.startswith("# "):
        cut = md.find("\n## ")
        md = md[cut + 1:] if cut != -1 else ""
    body, headings = mdrender.render(md)
    toc = "".join(f'<a href="#{_e(hid)}">{mdrender.inline(text)}</a>'
                  for level, hid, text in headings if level == 2)
    rd = Path(run_dir) if run_dir is not None else None
    parts = [
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width,initial-scale=1'>",
        # the page is opened from disk as often as it is served: carry its own
        # CSP so a missed escape would still be inert (R14)
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; "
        "style-src 'unsafe-inline'; form-action 'none'; base-uri 'none'\">",
        f"<title>security-council — {_e(manifest.get('run_id'))}</title>",
        f"<style>{_CSS}</style></head><body><div class='page'>",
        _dashboard(findings, manifest, rd),
        f'<nav class="toc">Sections: {toc}</nav>' if toc else "",
        "<main>", body, "</main>",
        "<footer>Validator verdicts demote but never hide a finding; crypto and critical "
        "findings are never auto-suppressed; a stored decision applies only with a verified "
        "signature. Print this page for a PDF copy; the markdown next to it is the "
        "system of record.</footer></div></body></html>",
    ]
    return "\n".join(p for p in parts if p)
