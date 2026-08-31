"""`summary.html` — the one-page report written on every scan (and
re-renderable with `report <run> --format html` / `report --open`).

Two parts. The DASHBOARD at the top is computed from the finding model and
the manifest: release decision, recommended action, related measures for
release risk, validation coverage and run confidence, a limitations box, and
a "Where to look" block that links every file the run produced —
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
from .. import rollup as _rollup
from ..model import Finding
from . import markdown as _markdown
from . import mdrender

_SEV_ORDER = ("critical", "high", "medium", "low", "info")
_SEV_RANK = {s: i for i, s in enumerate(_SEV_ORDER)}


def _e(v: object) -> str:
    """THE escaping boundary for the dashboard; the body uses mdrender.e."""
    return html.escape("" if v is None else str(v), quote=True)


def _system_label(manifest: dict) -> str:
    """Short display identity for the assessed system, separate from the title.

    A caller may provide ``report_identity.system_name``. Otherwise use the
    target directory name, which is stable, useful, and does not invent a
    long-form product name the scanner was never given.
    """
    identity = manifest.get("report_identity") or {}
    if identity.get("system_name"):
        return str(identity["system_name"])
    root = str((manifest.get("target") or {}).get("root") or "Assessed system")
    name = Path(root).name or root
    return name.upper() if len(name) <= 8 and name.replace("-", "").isalnum() else \
        name.replace("-", " ").replace("_", " ").title()


_CSS = """
:root { --ink:#182230; --mut:#627083; --canvas:#eef2f6; --surface:#fff; --soft:#f7f9fb;
        --line:#dce3eb; --navy:#0b1729; --navy2:#17385d; --crit:#c62936;
        --high:#e56a2e; --med:#a36b08; --low:#3978d4; --info:#627083;
        --ok:#178255; --warn:#a36b08; --failbg:#fff0f1; --okbg:#edf9f3;
        --warnbg:#fff8e8; --link:#1769c2; }
* { box-sizing:border-box; }
body { margin:0; color:var(--ink); background:var(--canvas);
       font:15px/1.5 Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif; }
.page { max-width:80rem; margin:0 auto; padding:1.4rem 1.25rem 3.5rem; }
h1,h2,h3,h4 { line-height:1.25; }
h1 { font-size:clamp(1.8rem,4vw,2.55rem); letter-spacing:-.035em; margin:.5rem 0 .6rem; }
h2 { font-size:1.28rem; letter-spacing:-.015em; margin-top:2.1rem; }
h3 { font-size:1.05rem; margin-top:1.6rem; }
code { font-family:ui-monospace,Consolas,monospace; font-size:.92em;
       background:#e9eef4; padding:.1em .35em; border-radius:4px; }
pre { background:var(--soft); border:1px solid var(--line); border-radius:9px;
      padding:.7rem .9rem; overflow-x:auto; }
pre code { background:none; padding:0; }
.tbl { overflow-x:auto; margin:.75rem 0; }
table { border-collapse:collapse; width:100%; }
th,td { border:1px solid var(--line); padding:.4rem .58rem; text-align:left;
        vertical-align:top; font-size:.92rem; }
th { background:var(--soft); }
blockquote { margin:.8rem 0; padding:.55rem .9rem; border-left:4px solid var(--warn);
             background:var(--warnbg); }
a { color:var(--link); }
.report-header { position:relative; overflow:hidden; color:var(--ink); padding:1.3rem 1.5rem 1.5rem;
                 border:1px solid var(--line); border-top:6px solid var(--navy); border-radius:18px;
                 background:var(--surface); box-shadow:0 10px 28px rgba(11,23,41,.08); }
.report-header:after { content:""; position:absolute; width:24rem; height:24rem; right:-9rem; top:-15rem;
                       border:1px solid #d9e7f6; border-radius:50%;
                       box-shadow:0 0 0 4rem rgba(57,120,212,.035),0 0 0 8rem rgba(57,120,212,.02); }
.report-header>* { position:relative; z-index:1; }
.brandline { display:flex; justify-content:space-between; align-items:center; gap:1rem; }
.brand { color:var(--low); font-size:.74rem; font-weight:800; letter-spacing:.13em; text-transform:uppercase; }
.badge { color:var(--navy); border:1px solid #9fb1c7; border-radius:999px; padding:.22rem .62rem;
         font-size:.7rem; font-weight:800; letter-spacing:.07em; text-transform:uppercase; }
.subtitle { color:var(--mut); max-width:54rem; margin:.2rem 0 0; }
.identity { display:grid; grid-template-columns:minmax(10rem,.7fr) minmax(18rem,1.3fr) minmax(10rem,.7fr);
            gap:1px; overflow:hidden; margin:1rem 0 .2rem; border:1px solid var(--line);
            border-radius:10px; background:var(--line); }
.identity-item { padding:.55rem .7rem; background:var(--soft); }
.identity-item span { display:block; color:var(--mut); font-size:.66rem; font-weight:800;
                      letter-spacing:.07em; text-transform:uppercase; }
.identity-item strong { display:block; color:var(--ink); margin-top:.06rem; font-size:.88rem; }
.report-header .meta { display:flex; flex-wrap:wrap; gap:.3rem 1rem; color:var(--mut); margin:1rem 0 0; font-size:.78rem; }
.report-header code { color:var(--ink); background:#e9eef4; }
.summary-label { color:var(--mut); font-size:.72rem; font-weight:800; letter-spacing:.1em;
                 text-transform:uppercase; margin:2rem 0 .45rem; }
.meta { color:var(--mut); font-size:.88rem; margin:0 0 .8rem; }
.policyline { background:var(--surface); border:1px solid var(--line); border-radius:10px;
              margin:.8rem 0; padding:.55rem .75rem; }
.decision { display:grid; grid-template-columns:minmax(0,1.3fr) minmax(18rem,.7fr); gap:.7rem; align-items:start; }
.gate { padding:1rem 1.1rem; border-radius:13px; font-weight:800; font-size:1.18rem; margin:0; background:var(--surface); }
.gate-note { display:block; max-width:46rem; margin-top:.35rem; color:var(--ink); font-size:.88rem; font-weight:400; }
.gate.fail { color:#901b26; border:1px solid #efc2c6; border-left:6px solid var(--crit); }
.gate.pass { color:var(--ok); border:1px solid #b9dfcd; border-left:6px solid var(--ok); }
.gate.warn { color:#765009; border:1px solid #ead9aa; border-left:6px solid var(--warn); }
.next { margin:0; padding:.9rem 1rem; background:var(--surface); border:1px solid var(--line);
        border-radius:13px; font-size:.9rem; }
.next:before { content:"Recommended action"; display:block; color:var(--mut); font-size:.7rem;
               font-weight:800; letter-spacing:.08em; text-transform:uppercase; margin-bottom:.2rem; }
.command-help { margin-top:.5rem; color:var(--mut); font-size:.8rem; }
.command-help summary { cursor:pointer; font-weight:700; }
.relations { display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:.7rem; margin:1rem 0; }
.relation { background:var(--surface); border:1px solid var(--line); border-radius:13px; padding:.9rem 1rem; }
.relation h2 { margin:0 0 .2rem; font-size:1.02rem; }
.relation-intro { min-height:2.5rem; color:var(--mut); font-size:.8rem; margin:0 0 .75rem; }
.relation-total { display:flex; align-items:baseline; gap:.45rem; padding:.55rem 0 .65rem;
                  border-bottom:1px solid var(--line); }
.relation-total strong { font-size:1.8rem; line-height:1; letter-spacing:-.04em; }
.relation-total span { color:var(--mut); font-size:.8rem; }
.relation-row { display:grid; grid-template-columns:minmax(0,1fr) auto; gap:.6rem; padding:.5rem 0;
                border-bottom:1px solid var(--line); align-items:baseline; }
.relation-row:last-of-type { border-bottom:0; }
.relation-row span { color:var(--mut); font-size:.82rem; }
.relation-row strong { font-size:1rem; font-variant-numeric:tabular-nums; }
.relation-row.block strong { color:var(--crit); }
.relation-row.warn strong { color:var(--warn); }
.relation-note { color:var(--mut); font-size:.76rem; margin:.65rem 0 0; }
.severity-line { display:flex; flex-wrap:wrap; gap:.3rem .65rem; margin:.65rem 0 0; font-size:.78rem; }
.severity-line span { white-space:nowrap; }
.sev { font-weight:800; text-transform:uppercase; font-size:.82em; }
.sev.critical { color:var(--crit); } .sev.high { color:var(--high); }
.sev.medium { color:var(--med); } .sev.low { color:var(--low); } .sev.info { color:var(--info); }
.box { background:var(--surface); border-radius:12px; padding:.8rem 1rem; margin:1rem 0;
       border:1px solid var(--line); }
.box.degr { background:var(--failbg); border-color:#efc2c6; border-left:5px solid var(--crit); }
.box.degr h2 { margin-top:0; color:#901b26; font-size:1.05rem; }
.box.degr p { margin:.2rem 0 .55rem; }
.technical { margin-top:.65rem; color:var(--mut); font-size:.82rem; }
.technical summary { cursor:pointer; font-weight:700; }
.box.look h2 { margin-top:0; font-size:1.05rem; }
.box ul { margin:.3rem 0 0 1.1rem; padding:0; }
details.engineering { margin-top:1.8rem; background:var(--surface); border:1px solid var(--line);
                      border-radius:14px; overflow:hidden; }
details.engineering>summary { cursor:pointer; padding:1rem 1.1rem; color:var(--navy); background:#edf3fa;
                              border-left:6px solid var(--low); font-size:1.05rem; font-weight:750; }
.engineering-body { padding:.1rem 1.1rem 1.1rem; }
nav.toc { font-size:.88rem; color:var(--mut); margin:.8rem 0 1rem; }
nav.toc a { margin-right:.9rem; white-space:nowrap; }
main ul { padding-left:1.3rem; } main li { margin:.15rem 0; }
footer { margin:2.5rem 0 1rem; color:var(--mut); font-size:.82rem;
         border-top:1px solid var(--line); padding-top:.8rem; }
@media (max-width:900px) { .relations { grid-template-columns:1fr; } .relation-intro { min-height:0; } }
@media (max-width:760px) { .page { padding:1rem .75rem 2rem; } .decision { grid-template-columns:1fr; }
                           .brandline { align-items:flex-start; } .identity { grid-template-columns:1fr; } }
@media print { body { background:#fff; } .page { max-width:none; padding:0; }
               .report-header { color:var(--ink); background:#fff; border:2px solid var(--navy); box-shadow:none; }
               .brand,.subtitle,.report-header .meta { color:var(--ink); }
               .badge { border-color:var(--ink); } .report-header code { color:var(--ink); background:var(--soft); }
               details.engineering>summary { display:none; } details.engineering>.engineering-body { display:block; }
               details.engineering { border:0; } .engineering-body { padding:0; }
               nav.toc { display:none; } pre { white-space:pre-wrap; } h2 { break-after:avoid; }
               .decision,.relations { break-inside:avoid; } }
"""

_EXIT = {
    0: ("pass", "PASS — no gating findings"),
    1: ("fail", "FAIL — gating findings present"),
    2: ("warn", "USAGE ERROR"),
    3: ("warn", "DEGRADED — partial results; this is NOT a clean bill"),
    4: ("fail", "ENTITLEMENT REFUSED — an undeclared gated model tier was requested"),
    5: ("fail", "PREFLIGHT REFUSED"),
}

_DECISION = {
    0: "RELEASE DECISION: CLEAR",
    1: "RELEASE DECISION: BLOCKED",
    2: "ASSESSMENT STATUS: INVALID",
    3: "ASSESSMENT STATUS: INCOMPLETE",
    4: "ASSESSMENT STATUS: REFUSED",
    5: "ASSESSMENT STATUS: PREFLIGHT FAILED",
}


def _gating(findings: list[Finding], manifest: dict) -> list[Finding]:
    return _policy.gating_findings(findings, manifest.get("policy") or {})


def _next_steps(exit_code, gating: list[Finding], manifest: dict) -> str:
    pol = manifest.get("policy") or {}
    thr = pol.get("fail_on_severity", "high")
    degr = manifest.get("degradations") or []
    if exit_code == 0:
        scope = (manifest.get("scan_scope") or {}).get("kind", "full")
        qualifier = ("" if scope == "full"
                     else f" in the scanned scope (<code>{_e(scope)}</code>)")
        msg = (f"No open finding at or above <code>{_e(thr)}</code>{qualifier}. "
               "Lower-severity findings, if any, are listed below and worth a "
               "look when convenient.")
    elif exit_code == 1:
        by = {}
        for f in gating:
            by[f.severity.label] = by.get(f.severity.label, 0) + 1
        parts = ", ".join(f"{n} {s}" for s, n in sorted(by.items(), key=lambda kv: _SEV_RANK.get(kv[0], 9)))
        msg = (f"<strong>{len(gating)} findings block promotion</strong> ({_e(parts)}). "
               "Fix or formally disposition them, then re-scan."
               "<details class=\"command-help\"><summary>Engineering commands</summary>"
               "Suppress a false positive with <code>security-council suppress &lt;id&gt; --operator you "
               "--justification \"…\" --signing-key ~/.ssh/id_ed25519</code>; or distinguish an accepted "
               "backlog with <code>baseline set</code> + <code>--gate-baseline new</code>.</details>")
    elif exit_code == 3:
        msg = (f"<strong>Degraded run</strong> — {len(degr)} problem(s) listed in the red box below. "
               "A scanner failed, verified nothing, or covered only part of the tree, so a clean "
               "result here would not mean clean code. Fix the cause and re-scan.")
    else:
        msg = "The run did not complete normally — see the gate banner and the degradations."
    return f'<div class="next">{msg}</div>'


def _safe_rel(path: object) -> str | None:
    """A manifest-supplied path is only ever linked if it is a plain RELATIVE
    path inside the run directory — no scheme, no `//`, no `..`, no leading
    `/`, no backslash, nothing that a browser could read as a URL to
    somewhere else (R14, codex: escaping made it inert as text but not as an
    href). Anything else is rendered as text, not a link."""
    s = "" if path is None else str(path).strip()
    if not s or len(s) > 400 or "\\" in s or "\x00" in s or ":" in s or "%" in s:
        return None                      # `%2e%2e` is a dot-dot segment to a browser (R14)
    if s.startswith(("/", "//", "#", "?")):
        return None
    parts = s.split("/")
    if any(part in ("..", "") for part in parts[:-1]) or parts[-1] == "..":
        return None
    return s


def _where_to_look(manifest: dict, run_dir: Path | None) -> str:
    rows: list[str] = []

    def link(rel: str, label: str, note: str = "") -> None:
        safe = _safe_rel(rel)
        shown = f'<a href="{_e(safe)}"><code>{_e(safe)}</code></a>' if safe else \
            f'<code>{_e(rel)}</code> <span class="meta">(not linked: not a path in this run)</span>'
        rows.append(f"<li>{shown} — {_e(label)}"
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
    arms = manifest.get("arms") or []
    ok = [a for a in arms if a.get("ok")]
    failed = [a for a in arms if not a.get("ok")]
    exit_code = manifest.get("exit_code")
    cls, _ = _EXIT.get(exit_code, ("warn", f"exit {exit_code}"))
    gating = _gating(findings, manifest)
    corroborated = [f for f in findings
                    if (f.corroboration.independent_family_count
                        or len(set(f.corroboration.vendor_families))) >= 2]
    # R15b: "validated" means a panel actually convened — the same predicate
    # the markdown uses; an unconvened needs_human is NOT cross-examined
    with_record = [f for f in findings if f.validation is not None]
    validated = [f for f in with_record if f.validation.convened()]
    quorum = [f for f in validated if len(f.validation.external_families()) >= 2]
    host_validated = [f for f in with_record if any(
        op.is_host and op.status != "absent" for op in f.validation.panel)]
    vm = manifest.get("validation") or {}
    degr = manifest.get("degradations") or []
    sp = manifest.get("signature_policy") or {}
    tgt = manifest.get("target") or {}
    src = manifest.get("config_source") or {}
    scope = (manifest.get("scan_scope") or {}).get("kind", "full")
    tool = (manifest.get("tool") or {}).get("security_council", "?")

    system_label = _system_label(manifest)
    # method and scope are FACTS from the manifest, never fixed branding: a
    # quick scanner pass must not present itself as a deep source-code review
    agentic = any(a.get("kind") == "agent_cli" and a.get("ok") for a in arms)
    imported = any(a.get("kind") == "import" and a.get("ok") for a in arms)
    method = ("Deep source-code security review" if agentic else
              "Consolidated security assessment" if imported else
              "Automated multi-scanner security review")
    badge = "Full scan" if scope == "full" else f"{scope.title()} scan"
    out = ['<header class="report-header"><div class="brandline">'
           '<span class="brand">Security Council</span>'
           f'<span class="badge">{_e(badge)}</span></div>',
           "<h1>Application Security Assessment</h1>",
           '<p class="subtitle">Decision-ready security posture with complete engineering evidence.</p>',
           '<div class="identity">'
           f'<div class="identity-item"><span>Assessed system</span><strong>{_e(system_label)}</strong></div>'
           f'<div class="identity-item"><span>Assessment</span><strong>{_e(method)}</strong></div>'
           f'<div class="identity-item"><span>Report ID</span><strong>{_e(manifest.get("run_id"))}</strong></div>'
           '</div>']
    meta = [f"target <code>{_e(tgt.get('root'))}</code>"]
    if tgt.get("git_commit"):
        meta.append(f"commit <code>{_e(str(tgt.get('git_commit'))[:12])}</code>")
    meta.append(f"{_e(manifest.get('started_at'))} → {_e(manifest.get('finished_at'))}")
    meta.append(f"security-council {_e(tool)}")
    if scope != "full":
        meta.append(f"<strong>⚠ partial — {_e(scope)} scan</strong>")
    out.append(f'<p class="meta"><span>security-council report — run '
               f'<code>{_e(manifest.get("run_id"))}</code></span>'
               f'<span>{"</span><span>".join(meta)}</span></p></header>')
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
    out.append(f'<p class="meta policyline">{" · ".join(line2)}</p>')
    out.append('<p class="summary-label">Leadership decision</p>')
    gate_note = {
        0: "No policy-gating exposure was observed in the completed scope.",
        1: "Promotion remains blocked until each gating path is remediated or formally dispositioned.",
        2: "Correct the invocation or configuration error before using this result.",
        3: "Restore complete coverage before treating this run as evidence of acceptable risk.",
        4: "Use only declared and approved model tiers before re-running the assessment.",
        5: "Resolve the preflight failure before starting another assessment.",
    }.get(exit_code, "Review the run degradations and evidence before making a release decision.")
    decision_label = _DECISION.get(exit_code, "ASSESSMENT STATUS: REVIEW REQUIRED")
    # A gate pass is only a RELEASE decision when the whole tree was in scope
    # and nothing degraded: a diff/partial run or a limited one must say so in
    # the headline itself — the banner is what gets screenshotted, not the
    # meta line under it.
    if exit_code == 0:
        excluded = (manifest.get("scan_scope") or {}).get("excluded")
        # unsigned operator state (a baseline) taking findings off the gate is
        # a limitation the headline must carry, same as a degradation (R17)
        baselined_out = (pol.get("gate_baseline") == "new"
                         and _policy.gating_findings(findings,
                                                     {**pol, "gate_baseline": "all"}))
        if scope != "full":
            decision_label = f"RELEASE DECISION: CLEAR FOR SCOPE ({scope.upper()})"
        elif excluded or degr or baselined_out:
            decision_label = "RELEASE DECISION: CLEAR — WITH LIMITATIONS"
    out.append(f'<div class="decision"><div class="gate {cls}">{_e(decision_label)}'
               f'<span class="gate-note">{_e(gate_note)}</span></div>'
               f'{_next_steps(exit_code, gating, manifest)}</div>')

    total = counts.get("total", len(findings))
    gating_by_sev = {s: sum(1 for f in gating if f.severity.label == s) for s in _SEV_ORDER}
    not_gating = max(0, total - len(gating))
    high_not_gating = max(0, sev.get("high", 0) - gating_by_sev["high"])
    severity_line = "".join(
        f'<span><strong class="sev {_e(s)}">{_e(n)} {_e(s)}</strong></span>'
        for s in _SEV_ORDER if (n := sev.get(s, 0)))

    external_count = len(validated)
    host_only = [f for f in host_validated if not f.validation.convened()]
    host_overlap = max(0, len(host_validated) - len(host_only))
    host_tag = f" ({_e(_markdown._host_label(with_record))})" if host_validated else ""
    other_records = max(0, len(with_record) - external_count - len(host_only))
    no_record = max(0, total - len(with_record))
    selected = vm.get("external_selected", 0)
    eligible = vm.get("eligible", 0)
    not_selected = vm.get("not_selected", 0)
    deterministic_skipped = vm.get("deterministic_skipped", 0)
    failed_external = vm.get("external_failed", 0)

    validation_extra = (f'<div class="relation-row"><span>Other carried record</span>'
                        f'<strong>{_e(other_records)}</strong></div>') if other_records else ""
    signature = sp.get("effective") or "off"
    failed_names = ", ".join(a.get("name", "?") for a in failed)
    out.append('<p class="summary-label">How the numbers relate</p>')
    out.append(
        '<div class="relations">'
        '<section class="relation"><h2>1. Release risk</h2>'
        '<p class="relation-intro">The blocking count is a subset of the total.</p>'
        f'<div class="relation-total"><strong data-metric="instances">{_e(total)}</strong>'
        '<span>observed finding instances</span></div>'
        f'<div class="relation-row block"><span>Blocking promotion</span>'
        f'<strong data-metric="gating">{_e(len(gating))}</strong></div>'
        f'<div class="relation-row"><span>Not blocking under current policy</span><strong>{_e(not_gating)}</strong></div>'
        f'<div class="severity-line">{severity_line}</div>'
        f'<p class="relation-note">{_e(len(gating))} = {_e(gating_by_sev["critical"])} critical + '
        f'{_e(gating_by_sev["high"])} high. {_e(high_not_gating)} high are non-gating.</p></section>'
        '<section class="relation"><h2>2. Validation coverage</h2>'
        '<p class="relation-intro">Grouped by the strongest review record present.</p>'
        f'<div class="relation-total"><strong>{_e(len(with_record))}</strong>'
        f'<span>with a validation record · {_e(no_record)} without</span></div>'
        f'<div class="relation-row"><span>External panel reviewed</span>'
        f'<strong data-metric="external-panel">{_e(external_count)}</strong></div>'
        f'<div class="relation-row"><span>Host-only record{host_tag}</span>'
        f'<strong>{_e(len(host_only))}</strong></div>'
        f'{validation_extra}'
        f'<div class="relation-row warn"><span>No validation record</span><strong>{_e(no_record)}</strong></div>'
        f'<p class="relation-note">{_e(eligible)} eligible = {_e(selected)} selected + '
        f'{_e(not_selected)} not selected. {_e(deterministic_skipped)} skipped. {_e(failed_external)} panel failed. '
        f'Host validation{host_tag}: {_e(host_overlap)} overlapping + '
        f'{_e(len(host_only))} host-only.</p></section>'
        '<section class="relation"><h2>3. Run confidence</h2>'
        '<p class="relation-intro">Health signals qualify the result; they do not add to it.</p>'
        f'<div class="relation-total"><strong>{_e(len(ok))}/{_e(len(arms))}</strong><span>scan arms completed</span></div>'
        f'<div class="relation-row"><span>Multi-vendor discovery corroboration</span><strong>{_e(len(corroborated))}</strong></div>'
        f'<div class="relation-row warn"><span>Run degradations</span><strong>{_e(len(degr))}</strong></div>'
        f'<div class="relation-row"><span>Two-vendor panel quorum</span><strong>{_e(len(quorum))}</strong></div>'
        f'<div class="relation-row"><span>Decision signatures</span><strong>{_e(signature)}</strong></div>'
        '<p class="relation-note">Corroboration means independent scanners found the same issue; it is not '
        f'validator review.{" Failed arms: " + _e(failed_names) + "." if failed_names else ""}</p></section>'
        '</div>')

    groups = _rollup.pattern_groups(findings)
    if groups:
        covered = sum(g.count for g in groups)
        rows = "".join(
            f'<tr><td><code>{_e(g.rule)}</code></td><td>{_e(g.family)}</td>'
            f'<td>{_e(g.count)}</td>'
            f'<td class="sev {_e(g.highest_severity)}">{_e(g.highest_severity)}</td>'
            f'<td>{_e(", ".join(g.components[:5]) or "—")}</td></tr>'
            for g in groups[:8])
        out.append(
            '<p class="summary-label">Concentration</p>'
            f'<div class="box"><p>{_e(len(groups))} recurring pattern(s) cover '
            f'{_e(covered)} of {_e(total)} finding instances. A repeated rule is '
            'not one proven root cause; every instance keeps its own entry in '
            'the findings below.</p>'
            '<div class="tbl"><table><tr><th>Pattern</th><th>Family</th>'
            '<th>Instances</th><th>Highest</th><th>Components</th></tr>'
            f'{rows}</table></div></div>')

    if degr:
        partial_arms = [str(d.get("arm")) for d in degr
                        if d.get("kind") == "partial_coverage" and d.get("arm")]
        overview: list[str] = []
        if failed_external:
            noun = "finding" if failed_external == 1 else "findings"
            overview.append(f"<li><strong>Validation gap:</strong> {_e(failed_external)} selected "
                            f"{noun} requires human review.</li>")
        if partial_arms:
            overview.append("<li><strong>Partial imported coverage:</strong> "
                            f"{_e(', '.join(partial_arms))} did not represent a complete scan.</li>")
        summarized = {"validator_failed", "partial_coverage"}
        remaining: dict[str, int] = {}
        for d in degr:
            kind = str(d.get("kind") or "other")
            if kind not in summarized:
                remaining[kind] = remaining.get(kind, 0) + 1
        for kind, count in sorted(remaining.items()):
            overview.append(f"<li><strong>{_e(kind.replace('_', ' ').title())}:</strong> "
                            f"{_e(count)} reported condition{'s' if count != 1 else ''}.</li>")
        technical = "".join(f"<li><code>{_e(d.get('kind'))}</code>"
                            + (f" <code>{_e(d.get('arm'))}</code>" if d.get("arm") else "")
                            + f" — {_e(d.get('detail'))}</li>" for d in degr)
        out.append('<div class="box degr"><h2>Run limitations</h2>'
                   f'<p>{_e(len(degr))} recorded conditions reduce confidence in this assessment.</p>'
                   f'<ul>{"".join(overview)}</ul>'
                   '<details class="technical"><summary>Technical details</summary>'
                   f'<ul>{technical}</ul></details></div>')
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
        f"<title>Application Security Assessment — {_e(_system_label(manifest))}</title>",
        f"<style>{_CSS}</style></head><body><div class='page'>",
        _dashboard(findings, manifest, rd),
        f'<details class="engineering"><summary>View {len(findings)} individual finding instances '
        'and engineering evidence</summary><div class="engineering-body">',
        f'<nav class="toc">Sections: {toc}</nav>' if toc else "",
        "<main>", body, "</main></div></details>",
        _where_to_look(manifest, rd),
        "<footer>Validator verdicts demote but never hide a finding; crypto and critical "
        "findings are never auto-suppressed; a stored decision applies only with a verified "
        "signature. Print this page for a PDF copy; the markdown next to it is the "
        "system of record.</footer></div></body></html>",
    ]
    return "\n".join(p for p in parts if p)
