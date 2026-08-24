"""Self-contained HTML report (`report --format html`) — also the PDF path
(print-friendly stylesheet; print-to-PDF from any browser).

Security posture mirrors the markdown exporter: ONE hardened escaping boundary
(`_e`, `html.escape` with quotes) through which EVERY dynamic value passes —
finding titles, snippets-adjacent text, LLM- and repo-derived strings are all
attacker-influenced. Zero JavaScript (native <details> elements only), zero
external assets (inline CSS, no fonts, no images), so the file is safe to open
from an untrusted run directory and works air-gapped. Content decisions are
the summary.md ones: gate banner, arms/method table, register, per-finding
details, demoted-not-hidden appendix, calibration wording rules ("fitted",
never "calibrated").
"""

from __future__ import annotations

import html

from ..model import Finding

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

_CSS = """
:root { --fg:#1a1f27; --bg:#ffffff; --mut:#5b6472; --line:#d8dde5; --card:#f5f7fa;
        --crit:#8f1d21; --high:#b3541e; --med:#8a6d1a; --low:#3a6ea5; --ok:#2f7d4f; }
* { box-sizing:border-box; }
body { margin:2rem auto; max-width:70rem; padding:0 1rem; color:var(--fg);
       background:var(--bg); font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif; }
h1,h2 { line-height:1.2; } h1 { font-size:1.5rem; } h2 { font-size:1.2rem; margin-top:2rem; }
code { font-family:ui-monospace,Consolas,monospace; font-size:.92em;
       background:var(--card); padding:.1em .35em; border-radius:4px; }
table { border-collapse:collapse; width:100%; margin:.75rem 0; }
th,td { border:1px solid var(--line); padding:.35rem .55rem; text-align:left;
        vertical-align:top; font-size:.92rem; }
th { background:var(--card); }
.gate { padding:.7rem 1rem; border-radius:8px; font-weight:600; margin:.8rem 0; }
.gate.fail { background:#fbeaea; color:var(--crit); border:1px solid var(--crit); }
.gate.pass { background:#e8f4ec; color:var(--ok); border:1px solid var(--ok); }
.sev { font-weight:700; text-transform:uppercase; font-size:.8rem; }
.sev.critical { color:var(--crit); } .sev.high { color:var(--high); }
.sev.medium { color:var(--med); } .sev.low, .sev.info { color:var(--low); }
.muted { color:var(--mut); } .badge { font-size:.8rem; color:var(--mut); }
details { border:1px solid var(--line); border-radius:8px; margin:.5rem 0;
          padding:.4rem .8rem; background:var(--card); }
summary { cursor:pointer; font-weight:600; }
footer { margin:2.5rem 0 1rem; color:var(--mut); font-size:.85rem;
         border-top:1px solid var(--line); padding-top:.8rem; }
@media print { details { break-inside:avoid; } details[open] summary { font-weight:700; }
               body { margin:0; max-width:none; } }
"""


def _e(v: object) -> str:
    """THE escaping boundary: every dynamic value passes here."""
    return html.escape("" if v is None else str(v), quote=True)


def _sev(label: str) -> str:
    return f'<span class="sev {_e(label)}">{_e(label)}</span>'


def _sort_key(f: Finding):
    return (_SEV_ORDER.get(f.severity.label, 9), f.id)


def _hidden(f: Finding) -> bool:
    return f.disposition.state == "refuted" or \
        f.disposition.lifecycle in ("suppressed", "accepted_risk", "fixed")


def _loc(f: Finding) -> str:
    if not f.locations:
        return "—"
    x = f.locations[0]
    return f"<code>{_e(x.uri)}:{_e(x.start_line)}-{_e(x.end_line)}</code>"


def _gate(manifest: dict) -> str:
    code = manifest.get("exit_code")
    if code == 0:
        return '<div class="gate pass">GATE: PASS — no gating findings</div>'
    label = {1: "FAIL — gating findings at/above the failure threshold",
             3: "DEGRADED — an arm failed or coverage is partial",
             4: "ENTITLEMENT REFUSED", 5: "PREFLIGHT REFUSED"}.get(code, f"exit {code}")
    return f'<div class="gate fail">GATE: {_e(label)}</div>'


def _arms_table(manifest: dict) -> list[str]:
    out = ["<h2>Method &amp; attestation</h2>",
           "<table><tr><th>Arm</th><th>Kind</th><th>Version / model</th>"
           "<th>Status</th><th>Raw → merged</th><th>Time</th></tr>"]
    for a in manifest.get("arms", []) or []:
        status = "ok" if a.get("ok") else f"FAILED — {a.get('error') or ''}"
        if a.get("classifier_fallback"):
            status = "MODEL SUBSTITUTION — arm dropped (D8)"
        model = a.get("tool_version") or ("unattested" if a.get("model_unattested") else "—")
        out.append(
            f"<tr><td>{_e(a.get('name'))}</td><td>{_e(a.get('kind'))}</td>"
            f"<td>{_e(model)}</td><td>{_e(status)}</td>"
            f"<td>{_e(a.get('raw_results'))} → {_e(a.get('normalized'))}</td>"
            f"<td>{_e(a.get('elapsed_seconds'))}s</td></tr>")
    out.append("</table>")
    cal = manifest.get("calibration") or {}
    if cal.get("status") == "active":
        out.append(f'<p class="badge">Score fitting (opt-in): record '
                   f'<code>{_e(cal.get("record"))}</code> — fitted base applied to '
                   f'{_e(cal.get("applied_findings", 0))} deterministic-singleton '
                   f'finding(s); floors still apply.</p>')
    return out


def _register(ordered: list[Finding], scores: dict | None) -> list[str]:
    out = ["<h2>Findings register</h2>",
           "<table><tr><th>#</th><th>Severity</th><th>State</th><th>Family / CWE</th>"
           "<th>Title</th><th>Location</th><th>Sources</th><th>Validation</th></tr>"]
    for i, f in enumerate(ordered, 1):
        v = f.validation
        if v is not None:
            val = f"{_e(v.verdict)} ({v.confidence:.2f})"
        elif scores and f.id in scores:
            val = f"p {scores[f.id]['p']:.2f} fitted"
        else:
            val = "—"
        srcs = ", ".join(sorted({p.source_id for p in f.provenance}))
        out.append(
            f"<tr><td>{i}</td><td>{_sev(f.severity.label)}</td>"
            f"<td>{_e(f.disposition.state)}</td>"
            f"<td>{_e(f.taxonomy.cwe_family or '—')} / {_e(', '.join(f.taxonomy.cwe[:2]))}</td>"
            f"<td>{_e(f.title)}</td><td>{_loc(f)}</td><td>{_e(srcs)}</td>"
            f"<td>{val}</td></tr>")
    out.append("</table>")
    return out


def _detail(i: int, f: Finding, scores: dict | None) -> list[str]:
    out = [f"<details><summary>{i}. {_sev(f.severity.label)} {_e(f.title)}</summary>"]
    out.append(f"<p><span class='muted'>id</span> <code>{_e(f.id)}</code> · "
               f"{_e(', '.join(f.taxonomy.cwe))} ({_e(f.taxonomy.cwe_family or '—')}) · "
               f"rule <code>{_e(f.rule.id)}</code><br>"
               f"<span class='muted'>location</span> {_loc(f)}<br>"
               f"<span class='muted'>reported by</span> "
               f"{_e('; '.join(sorted({p.source_id for p in f.provenance})))}</p>")
    if f.description:
        out.append(f"<p>{_e(f.description)}</p>")
    if f.validation is None and scores and f.id in scores:
        s = scores[f.id]
        extra = ""
        if s.get("clamps"):
            extra = (f" (measured {s.get('measured_p', s['p']):.2f}; deployed value "
                     f"raised by {_e(', '.join(s['clamps']))})")
        out.append(f"<p><span class='muted'>score</span> p {s['p']:.2f} — fitted base "
                   f"from record <code>{_e(s.get('record'))}</code>{extra}</p>")
    v = f.validation
    if v is not None:
        out.append(f"<p><span class='muted'>validation</span> {_e(v.verdict)} "
                   f"(confidence {v.confidence:.2f}) → state "
                   f"<code>{_e(f.disposition.state)}</code></p>")
    out.append("</details>")
    return out


def to_html(findings: list[Finding], manifest: dict, *, scores: dict | None = None) -> str:
    ordered = sorted([f for f in findings if not _hidden(f)], key=_sort_key)
    demoted = sorted([f for f in findings if _hidden(f)], key=_sort_key)
    counts = manifest.get("counts") or {}
    sev = counts.get("by_severity") or {}
    parts = [
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width,initial-scale=1'>",
        f"<title>security-council — {_e(manifest.get('run_id'))}</title>",
        f"<style>{_CSS}</style></head><body>",
        f"<h1>security-council report — run <code>{_e(manifest.get('run_id'))}</code></h1>",
        f"<p class='muted'>target <code>{_e((manifest.get('target') or {}).get('root'))}</code>"
        + (f" · git <code>{_e((manifest.get('target') or {}).get('git_commit', '')[:12])}</code>"
           if (manifest.get('target') or {}).get('git_commit') else "") + "</p>",
        _gate(manifest),
        "<p>" + " · ".join(f"{_sev(k)} {_e(n)}" for k, n in sorted(
            sev.items(), key=lambda kv: _SEV_ORDER.get(kv[0], 9))) + "</p>",
    ]
    parts += _arms_table(manifest)
    parts += _register(ordered, scores)
    if ordered:
        parts.append("<h2>Findings</h2>")
        for i, f in enumerate(ordered, 1):
            parts += _detail(i, f, scores)
    if demoted:
        parts.append("<h2>Appendix — demoted and closed findings</h2>")
        parts.append("<p class='muted'>Demoted, never hidden: these left the gate "
                     "but remain listed.</p>")
        for i, f in enumerate(demoted, 1):
            parts += _detail(i, f, scores)
    parts.append(
        "<footer>Validator verdicts demote but never hide a finding; crypto findings "
        "are never auto-suppressed. Print this page for a PDF copy.</footer></body></html>")
    return "\n".join(parts)
