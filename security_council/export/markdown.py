"""Markdown executive summary.

The human-readable report: what ran (method + model attestation, per D8), what was
found (register + details), how strongly each finding is corroborated and
validated, and what was demoted — never hidden — by the validator.

Everything rendered here is *untrusted text*: titles, descriptions, rationale and
citations originate from LLM arms and scanners reading an arbitrary repository,
so a hostile repo can try to smuggle markdown/HTML (image beacons, links, raw
HTML, table breakouts) into the report. `_esc` neutralizes that at the boundary:
markdown-significant punctuation is backslash-escaped, control characters are
stripped, bare URLs are defanged, and snippets go into fences sized to contain
any backtick run they carry. Keep every untrusted string on that path.
"""

from __future__ import annotations

import posixpath
import re

from ..model import CLOSED_LIFECYCLES, Finding

_SEV_ORDER = ("critical", "high", "medium", "low", "info")
_SEV_RANK = {s: i for i, s in enumerate(_SEV_ORDER)}
_STATE_ORDER = ("validated", "likely", "new", "disputed", "needs_human", "refuted")
_STATE_RANK = {s: i for i, s in enumerate(_STATE_ORDER)}

EXIT_LABELS = {0: "PASS — no gating findings", 1: "FAIL — gating findings present",
               2: "usage error", 3: "DEGRADED — partial results"}

_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")
_SPECIAL_RE = re.compile(r"([\\`*_\[\]<>|~])")
_LINE_START_RE = re.compile(r"(?m)^(\s*)([#>]|[-+]\s|\d+[.)]\s)")
_URL_RE = re.compile(r"(?i)\b(https?|ftp)(://)")
_FENCE_RE = re.compile(r"`{3,}")

_LANG_BY_EXT = {
    "py": "python", "js": "javascript", "mjs": "javascript", "ts": "typescript", "tsx": "tsx",
    "jsx": "jsx", "go": "go", "java": "java", "kt": "kotlin", "rb": "ruby", "php": "php",
    "cs": "csharp", "c": "c", "h": "c", "cpp": "cpp", "cc": "cpp", "hpp": "cpp", "rs": "rust",
    "sh": "bash", "bash": "bash", "yaml": "yaml", "yml": "yaml", "json": "json", "xml": "xml",
    "html": "html", "sql": "sql", "tf": "hcl", "toml": "toml", "swift": "swift", "scala": "scala",
}


# --------------------------------------------------------------------------- #
# Escaping (the trust boundary of this module)
# --------------------------------------------------------------------------- #


def _esc(text: object, *, limit: int | None = None, inline: bool = True) -> str:
    """Neutralize untrusted text for inclusion in markdown prose.

    inline=True collapses all whitespace to single spaces (titles, cells);
    inline=False keeps paragraph breaks but disarms line-leading block syntax.
    """
    s = "" if text is None else str(text)
    s = _CTRL_RE.sub("", s)
    if limit is not None and len(s) > limit:
        s = s[: max(0, limit - 1)].rstrip() + "…"
    s = _SPECIAL_RE.sub(r"\\\1", s)
    s = _URL_RE.sub(lambda m: m.group(1)[0] + "xx" + m.group(1)[3:] + m.group(2), s)  # defang
    if inline:
        s = re.sub(r"\s+", " ", s).strip()
    else:
        s = re.sub(r"[ \t]+\n", "\n", s)
        s = re.sub(r"\n{3,}", "\n\n", s).strip()
        s = _LINE_START_RE.sub(lambda m: m.group(1) + "\\" + m.group(2), s)
    return s


def _cell(text: object, limit: int | None = None) -> str:
    """Escape for a GFM table cell (inline; `_esc` already turns `|` into `\\|`)."""
    return _esc(text, limit=limit, inline=True)


def _enum(value: object) -> str:
    """Render a *trusted* model enum (state, verdict, family, ...) without escaping.

    Only for values constrained by the finding model's Literal types / invariants;
    anything that can carry free text goes through `_esc`/`_cell` instead.
    """
    s = re.sub(r"\s+", " ", _CTRL_RE.sub("", "" if value is None else str(value))).strip()
    return s.replace("|", "\\|")


def _code(text: object, limit: int = 120, *, cell: bool = False) -> str:
    """Inline code span for identifiers; backticks and newlines stripped."""
    s = _CTRL_RE.sub("", "" if text is None else str(text)).replace("`", "'")
    s = re.sub(r"\s+", " ", s).strip()
    if len(s) > limit:
        s = s[: limit - 1] + "…"
    if cell:
        s = s.replace("|", "\\|")
    return f"`{s}`" if s else ""


def _fence(snippet: str, uri: str, *, max_lines: int = 40, max_chars: int = 4000) -> list[str]:
    body = _CTRL_RE.sub("", snippet).replace("\r\n", "\n")
    lines = body.split("\n")
    truncated = False
    if len(lines) > max_lines:
        lines, truncated = lines[:max_lines], True
    body = "\n".join(lines)
    if len(body) > max_chars:
        body, truncated = body[:max_chars], True
    if truncated:
        body += "\n… (truncated)"
    longest = max((len(m.group(0)) for m in _FENCE_RE.finditer(body)), default=0)
    fence = "`" * max(3, longest + 1)
    lang = _LANG_BY_EXT.get(uri.rsplit(".", 1)[-1].lower(), "") if "." in uri else ""
    return [fence + lang, body, fence]


# --------------------------------------------------------------------------- #
# Small formatters
# --------------------------------------------------------------------------- #


def _loc(loc, *, cell: bool = False) -> str:
    rng = f"{loc.start_line}" if loc.end_line == loc.start_line else f"{loc.start_line}-{loc.end_line}"
    return _code(f"{loc.uri}:{rng}", cell=cell)


def _sev_badge(label: str) -> str:
    return f"**{label.upper()}**"


def _sort_key(f: Finding):
    return (_SEV_RANK.get(f.severity.label, 99), _STATE_RANK.get(f.disposition.state, 99), f.id)


def _is_demoted(f: Finding) -> bool:
    d = f.disposition
    return d.state == "refuted" or d.lifecycle in CLOSED_LIFECYCLES or \
        d.vex_status in ("not_affected", "fixed")


def _validation_summary(f: Finding, scores: dict | None = None) -> str:
    v = f.validation
    if v is None:
        s = (scores or {}).get(f.id)
        # (d)-lite (R7): a strict-scope fitted score for an unvalidated
        # deterministic singleton — post-clamp value, never the word "calibrated"
        return f"p {s['p']:.2f} fitted" if s else "—"
    return f"{v.verdict} ({v.confidence:.2f})"


def _sources_summary(f: Finding) -> str:
    c = f.corroboration
    srcs = sorted(set(c.agent_sources) | set(c.deterministic_sources))
    fam = c.independent_family_count or len(set(c.vendor_families))
    flags = []
    if c.singleton_by_policy:
        flags.append("singleton-by-policy")
    if c.uncovered:
        flags.append("uncovered")
    tail = f" ⚠ {', '.join(flags)}" if flags else ""
    return f"{', '.join(srcs) or '—'} ({len(srcs)} src / {fam} vendor){tail}"


# --------------------------------------------------------------------------- #
# Sections
# --------------------------------------------------------------------------- #


def _header(manifest: dict, findings: list[Finding]) -> list[str]:
    tgt = manifest.get("target", {}) or {}
    tool = (manifest.get("tool") or {}).get("security_council", "?")
    exit_code = manifest.get("exit_code")
    out = [f"# security-council report — run {_code(manifest.get('run_id', '?'))}", ""]
    out.append(f"- **Target:** {_code(tgt.get('root', '?'))}")
    git_bits = []
    if tgt.get("git_commit"):
        git_bits.append(f"commit {_code(str(tgt['git_commit'])[:12])}")
    if tgt.get("branch"):
        git_bits.append(f"branch {_code(tgt['branch'])}")
    if tgt.get("dirty") is not None:
        git_bits.append("working tree **dirty**" if tgt["dirty"] else "working tree clean")
    if git_bits:
        out.append(f"- **Revision:** {' · '.join(git_bits)}")
    out.append(f"- **Run:** {_esc(manifest.get('started_at', '?'))} → "
               f"{_esc(manifest.get('finished_at', '?'))} · security-council {_code(tool)}")
    scope = manifest.get("scan_scope") or {}
    if scope.get("kind") and scope["kind"] != "full":
        rng = (f"working-tree vs {scope.get('base') or 'HEAD'}" if scope["kind"] == "working_tree"
               else f"{scope.get('base') or 'auto'}..{scope.get('head') or 'HEAD'}")
        out.append(f"- **Scope:** ⚠ partial — change-scoped scan ({_esc(rng)}); "
                   "not a full-repository result, not baseline-eligible")
    pol = manifest.get("policy", {}) or {}
    armed = bool(pol.get("auto_suppress")) and bool(pol.get("accept_suppression_risk"))
    acts = manifest.get("disposition_actions") or {}
    suppress = "off" if not armed else ("shadow" if acts.get("shadow_suppress") else "on")
    out.append(f"- **Policy:** fail on ≥ {_code(pol.get('fail_on_severity', 'high'))} · "
               f"min arms ok {_code(pol.get('min_arms_ok', 1))} · auto-suppress {suppress}")
    if exit_code is not None:
        out.append(f"- **Gate:** {EXIT_LABELS.get(exit_code, f'exit {exit_code}')} (exit {exit_code})")
    out.append("")
    return out


def _summary(findings: list[Finding], manifest: dict) -> list[str]:
    out = ["## At a glance", ""]
    if not findings:
        out += ["No findings were produced by any arm.", ""]
    else:
        by_sev = {s: 0 for s in _SEV_ORDER}
        for f in findings:
            by_sev[f.severity.label] = by_sev.get(f.severity.label, 0) + 1
        sev_txt = " · ".join(f"{by_sev[s]} {s}" for s in _SEV_ORDER if by_sev[s])
        corroborated = sum(1 for f in findings if f.corroboration.independent_family_count >= 2)
        singles = sum(1 for f in findings if f.corroboration.singleton_by_policy)
        uncovered = sum(1 for f in findings if f.corroboration.uncovered)
        validated = [f for f in findings if f.validation is not None]
        tp = sum(1 for f in validated if f.validation.verdict == "true_positive")
        fp = sum(1 for f in validated if f.validation.verdict == "false_positive")
        nh = sum(1 for f in validated if f.validation.verdict in ("needs_human", "uncertain"))
        demoted = sum(1 for f in findings if _is_demoted(f))
        out.append(f"- **{len(findings)} findings** (root-cause clusters): {sev_txt}")
        out.append(f"- **Corroboration:** {corroborated} confirmed by ≥2 independent vendor families · "
                   f"{singles} only one eligible arm (singleton-by-policy) · {uncovered} uncovered")
        if validated:
            out.append(f"- **Validator panel:** {len(validated)} cross-examined → {tp} true positive · "
                       f"{fp} false positive (demoted) · {nh} need human review")
        else:
            out.append("- **Validator panel:** not run (`--validate` to cross-examine findings)")
        if demoted:
            out.append(f"- **Demoted, not hidden:** {demoted} finding(s) refuted or closed — see appendix")
        bd = manifest.get("baseline_delta")
        if bd:
            out.append(f"- **Baseline** (vs run {_code(bd.get('baseline_run', '?'))}): "
                       f"{bd.get('new', 0)} new · {bd.get('unchanged', 0)} unchanged · "
                       f"{bd.get('updated', 0)} updated · {bd.get('absent', 0)} absent")
            # R9: the baseline decides what does NOT gate, so its provenance is
            # shown every run — set by whom, when, and the digest to compare.
            prov = []
            if bd.get("operator"):
                prov.append(f"set by {_code(bd['operator'])}")
            if bd.get("set_at"):
                prov.append(f"on {_cell(str(bd['set_at'])[:10])}")
            if bd.get("content_sha256"):
                prov.append(f"digest {_code(str(bd['content_sha256'])[:12])}")
            if bd.get("integrity") == "unpinned":
                prov.append("⚠ no integrity digest (created before pinning)")
            if prov:
                out.append(f"  - baseline provenance: {' · '.join(prov)}")
        prior = manifest.get("prior_decisions") or []
        reapplied = [p for p in prior if str(p.get("action", "")).startswith("reapplied")]
        reopened = [p for p in prior if str(p.get("action", "")).startswith("reopened")]
        malformed = [p for p in prior if p.get("action") == "ignored_malformed"]
        if prior:
            bits = []
            if reapplied:
                bits.append(f"{len(reapplied)} suppression(s) reapplied")
            for p in reopened:
                why = "expired" if p["action"] == "reopened_expired" else "context drift"
                bits.append(f"finding {_code(p.get('finding_id', '?'))} REOPENED ({why})")
            for p in malformed:
                bits.append(f"finding {_code(p.get('finding_id', '?'))} decision IGNORED "
                            "(malformed record)")
            out.append(f"- **Decision store:** {' · '.join(bits)}")
        out.append("")
    # R9: every reapplied suppression is listed individually. An aggregate count
    # is the false-confidence surface — a hidden finding nobody re-reads. This
    # renders PROVENANCE (who, when, expires, how many times), never assurance.
    prior = manifest.get("prior_decisions") or []
    reapplied = [p for p in prior if str(p.get("action", "")).startswith("reapplied")]
    if reapplied:
        out.append("### Suppressions reapplied from the decision store")
        out.append("")
        out.append("_These findings were hidden from the gate by a stored operator decision. "
                   "The store is unsigned local state: review this list._")
        out.append("")
        out.append("| Finding | Severity | Title | Decided by | On | Expires | Times reapplied |")
        out.append("|---|---|---|---|---|---|---|")
        for p in sorted(reapplied, key=lambda r: _SEV_RANK.get(r.get("severity"), 9)):
            n = p.get("reapplied_count", 1)
            stale = " ⚠ stale" if isinstance(n, int) and n >= 5 else ""
            ha = " 🔒 high-assurance" if p.get("high_assurance") else ""
            clamp = " (expiry shortened)" if p.get("expiry_clamped") else ""
            out.append(f"| {_code(p.get('finding_id', '?'))} | "
                       f"{_sev_badge(str(p.get('severity', 'info')))}{ha} | "
                       f"{_cell(p.get('title', ''), 60)} | "
                       f"{_cell(p.get('operator') or 'unattributed')} | "
                       f"{_cell(str(p.get('decided_at') or '—')[:10])} | "
                       f"{_cell(str(p.get('expires_at') or '—')[:10])}{clamp} | "
                       f"{n}{stale} |")
        out.append("")
    degr = manifest.get("degradations") or []
    if degr:
        out.append("> ⚠️ **Degraded run** — results are partial:")
        for d in degr:
            kind = _enum(d.get("kind", "?"))
            arm = f" `{_esc(d['arm'])}`" if d.get("arm") else ""
            out.append(f"> - {kind}{arm}: {_esc(d.get('detail', ''), limit=300)}")
        out.append("")
    return out


def _method(findings: list[Finding], manifest: dict) -> list[str]:
    out = ["## Method & attestation", "",
           "| Arm | Kind | Vendor | Model / version | Status | Raw → merged | Time | Cost |",
           "|---|---|---|---|---|---|---|---|"]
    substituted = []
    for a in manifest.get("arms", []) or []:
        status = "ok" if a.get("ok") else f"**FAILED** — {_cell(a.get('error') or '', 120)}"
        if a.get("coverage_unverified"):
            status += " · ⚠ coverage unverified"
        if a.get("completion") and a.get("completion") != "complete":
            status += f" · completion {_cell(a['completion'])}"
        if a.get("cost_stopped"):
            status += " · ⚠ cost-stopped"
        if a.get("classifier_fallback"):
            status = f"**MODEL SUBSTITUTION** — {_cell(a.get('error') or '', 120)}"
            substituted.append(a.get("name", "?"))
        model = a.get("tool_version") or ("unattested" if a.get("model_unattested") else "—")
        raw = a.get("raw_results")
        norm = a.get("normalized")
        cnt = f"{raw if raw is not None else '?'} → {norm if norm is not None else '?'}"
        cost = a.get("cost_usd")
        out.append(f"| {_cell(a.get('name'))} | {_enum(a.get('kind'))} | {_cell(a.get('family'))} | "
                   f"{_cell(model, 60)} | {status} | {cnt} | "
                   f"{a.get('elapsed_seconds', 0)}s | {f'${cost:.2f}' if isinstance(cost, (int, float)) else '—'} |")
    out.append("")
    if substituted:
        out.append(f"> ❌ **Model substitution detected** on {', '.join(_code(s) for s in substituted)}: "
                   "the CLI served a different model than pinned. The arm was dropped rather than "
                   "attributing findings to the wrong model (decision D8).")
        out.append("")
    models: dict[str, set[str]] = {}
    postures: set[str] = set()          # only the noteworthy ones (default is the norm)
    relaxed_sources: set[str] = set()
    for f in findings:
        for p in f.provenance:
            if p.source_kind == "agent_cli" and p.model_id:
                models.setdefault(p.source_id, set()).add(p.model_id)
                if p.safeguard_posture == "relaxed":
                    postures.add("relaxed")
                    relaxed_sources.add(p.source_id)
                elif p.safeguard_posture == "unknown":
                    postures.add("unknown")
            if p.classifier_fallback:
                postures.add("classifier-fallback")
    if models:
        bits = [f"{_code(src)} ← {', '.join(_code(m) for m in sorted(ms))}" for src, ms in sorted(models.items())]
        out.append(f"- **Models that produced findings:** {'; '.join(bits)}")
    if relaxed_sources:
        out.append(f"- ⚠ **Relaxed-safeguard tier in use:** {', '.join(_code(s) for s in sorted(relaxed_sources))} "
                   "ran on a gated tier with safeguards relaxed (Mythos / Daybreak) — findings and "
                   "any dual-use content reflect that posture.")
    if postures:
        out.append(f"- **Safeguard posture seen:** {', '.join(sorted(postures))}")
    panel: dict[str, set[str]] = {}
    for f in findings:
        if f.validation:
            for op in f.validation.panel:
                panel.setdefault(op.participant, set()).add(op.model_id or "?")
    if panel:
        bits = [f"{_code(p)} ({', '.join(_code(m) for m in sorted(ms))})" for p, ms in sorted(panel.items())]
        out.append(f"- **Validator panel participants:** {'; '.join(bits)} — roles prosecutor / "
                   "defender / adjudicator on different vendors; every citation re-verified "
                   "against the repository")
    out.append("- **Clustering:** findings are grouped by root cause across arms; fingerprints are "
               "line-drift-stable and never contain line numbers.")
    cal = manifest.get("calibration") or {}
    status = cal.get("status")
    if status == "active":
        n = cal.get("applied_findings", 0)
        out.append(f"- **Score fitting (opt-in):** record {_code(cal.get('record', '?'))} active — "
                   f"fitted base applied to {n} deterministic-singleton finding(s); every other "
                   "finding is scored on the hand-set prior. Fitted values are corpus-scoped "
                   "(see the record's caveats) and all fail-safe floors still apply.")
        for w in cal.get("warnings") or []:
            out.append(f"  - ⚠ {_esc(str(w))}")
    elif status == "refused_pin_mismatch":
        out.append(f"- ⚠ **Score fitting refused:** record {_code(cal.get('record', '?'))} does not "
                   f"match this run's scanner pins ({_esc('; '.join(cal.get('mismatches') or []))}) — "
                   "scores fall back to the hand-set prior.")
    elif status == "invalid":
        out.append(f"- ⚠ **Score fitting record invalid:** {_esc('; '.join(cal.get('problems') or []))} "
                   "— scores fall back to the hand-set prior.")
    out.append("")
    return out


def _register(ordered: list[Finding], scores: dict | None = None) -> list[str]:
    if not ordered:
        return []
    out = ["## Findings register", "",
           "| # | Severity | State | Family / CWE | Title | Location | Sources | Validation |",
           "|---|---|---|---|---|---|---|---|"]
    for i, f in enumerate(ordered, 1):
        cwe = _cell(", ".join(f.taxonomy.cwe[:2]))
        loc = _loc(f.locations[0], cell=True) if f.locations else "—"
        out.append(f"| {i} | {_sev_badge(f.severity.label)} | {_enum(f.disposition.state)} | "
                   f"{_enum(f.taxonomy.cwe_family)} / {cwe} | {_cell(f.title, 70)} | {loc} | "
                   f"{_cell(_sources_summary(f))} | {_enum(_validation_summary(f, scores))} |")
    out.append("")
    return out


def _detail(i: int, f: Finding, scores: dict | None = None) -> list[str]:
    out = [f"### {i}. {_sev_badge(f.severity.label)} {_esc(f.title, limit=160) or _code(f.rule.id)}", ""]
    out.append(f"- **id** {_code(f.id)}" + (f" · cluster {_code(f.cluster_id)}" if f.cluster_id else "")
               + f" · {_cell(', '.join(f.taxonomy.cwe))} ({_enum(f.taxonomy.cwe_family)}, "
               f"{_enum(f.taxonomy.cwe_confidence)}) · rule {_code(f.rule.id)}")
    primary = f.locations[0] if f.locations else None
    if primary:
        rel = [_loc(loc) + (f" ({_enum(loc.role)})" if loc.role != "primary" else "")
               for loc in f.locations[1:6]]
        more = f" … +{len(f.locations) - 6} more" if len(f.locations) > 6 else ""
        out.append(f"- **location** {_loc(primary)}" + (f" · also at: {', '.join(rel)}{more}" if rel else ""))
    c = f.corroboration
    srcs = []
    for p in f.provenance:
        tag = f"{p.source_id} ({p.family}"
        if p.model_id:
            tag += f", {p.model_id}"
        tag += ")"
        if tag not in srcs:
            srcs.append(tag)
    line = (f"- **reported by** {_esc('; '.join(srcs))} — {c.count} source(s) / "
            f"{c.independent_family_count} vendor family(ies) · corroboration "
            f"{c.corroboration_score:.2f}/{c.coverage_denominator:.2f}")
    flags = []
    if c.singleton_by_policy:
        flags.append("only one arm was eligible to report this category (no cross-check possible)")
    if c.uncovered:
        flags.append("no eligible arm covers this category — coverage gap")
    if c.declined_sources:
        flags.append(f"eligible but silent: {_esc(', '.join(c.declined_sources))}")
    if c.independence_warning:
        w = c.independence_warning
        flags.append(f"independence warning: {w.get('distinct_vendors')} < {w.get('required')} vendors")
    out.append(line)
    for fl in flags:
        out.append(f"  - ⚠ {fl}")
    if f.validation is None and scores and f.id in scores:
        s = scores[f.id]
        srow = f"- **score** p {s['p']:.2f} — fitted base from record {_code(s.get('record', '?'))}"
        if s.get("clamps"):
            srow += (f" (measured {s.get('measured_p', s['p']):.2f}; deployed value raised by "
                     f"{_esc(', '.join(s['clamps']))})")
        out.append(srow)
    v = f.validation
    if v is not None:
        out.append(f"- **validation** {_enum(v.verdict)} (confidence {v.confidence:.2f}) → state "
                   f"{_code(f.disposition.state)}"
                   + (" · lifecycle remains **open** (auto-demote, never auto-close)"
                      if f.disposition.state == "refuted" and f.disposition.lifecycle == "open" else ""))
        ec = v.evidence_check or {}
        if ec:
            out.append(f"  - citations: {ec.get('citations_verified', 0)}/{ec.get('citations_total', 0)} "
                       f"verified · {ec.get('hallucinated', 0)} hallucinated"
                       + (" · **defender hallucinated → escalated**" if ec.get("defender_hallucinated") else ""))
        if v.panel:
            out.append("")
            out.append("  | Role | Participant | Model | Verdict | Citations | Status |")
            out.append("  |---|---|---|---|---|---|")
            for op in v.panel:
                ver = sum(1 for ct in op.citations if ct.verified is True)
                out.append(f"  | {_enum(op.role)} | {_cell(op.participant)} | {_cell(op.model_id or '—', 40)} | "
                           f"{_enum(op.verdict)} | {ver}/{len(op.citations)} | {_enum(op.status)} |")
            out.append("")
            for op in v.panel:
                if op.rationale:
                    out.append(f"  - *{_enum(op.role)}*: {_esc(op.rationale, limit=400)}")
    else:
        out.append(f"- **validation** not run · state {_code(f.disposition.state)}")
    if f.package:
        pk = f.package
        bits = [_code(pk.purl)]
        if pk.version:
            bits.append(f"installed {_code(pk.version)}")
        if pk.fixed_version:
            bits.append(f"fixed in {_code(pk.fixed_version)}")
        if pk.advisory_ids:
            bits.append(", ".join(_code(a) for a in pk.advisory_ids[:5]))
        out.append(f"- **package** {' · '.join(bits)}")
    if f.description and f.description != f.title:
        out.append("")
        out.append(_esc(f.description, limit=1500, inline=False))
    if primary and primary.snippet and not f.package:   # a manifest line says nothing about a CVE
        out.append("")
        out += _fence(primary.snippet, primary.uri)
    elif primary and f.taxonomy.cwe_family == "secrets":
        out.append("")
        out.append("_snippet redacted (secret material)_")
    if f.remediation and f.remediation.summary:
        out.append("")
        out.append(f"**Remediation:** {_esc(f.remediation.summary, limit=600)}"
                   + (f" (effort {_enum(f.remediation.effort)})" if f.remediation.effort else ""))
        if f.remediation.guidance:
            out.append("")
            out.append(_esc(f.remediation.guidance, limit=1200, inline=False))
    if f.rule.help_uri:
        out.append(f"- **reference** {_esc(f.rule.help_uri, limit=200)}")
    out.append("")
    return out


def _appendix(ordered: list[Finding]) -> list[str]:
    demoted = [(i, f) for i, f in enumerate(ordered, 1) if _is_demoted(f)]
    if not demoted:
        return []
    out = ["## Appendix — demoted and closed findings", "",
           "These findings remain in `merged.sarif` (as `suppressions[]`) and `findings.json`; "
           "nothing is deleted. A refuted finding is demoted by the validator panel but its "
           "lifecycle stays open until a human (or a later, attributed policy decision) closes it.", "",
           "| # | Severity | Title | State / lifecycle | Decided by | Reason |", "|---|---|---|---|---|---|"]
    for i, f in enumerate(ordered, 1):
        if not _is_demoted(f):
            continue
        d = f.disposition
        who = d.decided_by.kind
        if d.decided_by.operator:
            who += f" ({d.decided_by.operator})"
        elif d.decided_by.model_id:
            who += f" ({d.decided_by.model_id})"
        # composed only of model enums + timestamps (no free text) -> _enum is sufficient
        reason = d.vex_justification or ""
        if not reason and f.validation is not None:
            reason = f"panel {f.validation.verdict} ({f.validation.confidence:.2f})"
        if d.expires_at:
            reason += f" · expires {d.expires_at}"
        out.append(f"| {i} | {_sev_badge(f.severity.label)} | {_cell(f.title, 70)} | "
                   f"{_enum(d.state)} / {_enum(d.lifecycle)} | {_cell(who, 60)} | {_enum(reason)[:160]} |")
    out.append("")
    return out


def _analysis_artifacts(manifest: dict) -> list[str]:
    arts = manifest.get("artifacts") or []
    if not arts:
        return []
    out = ["## Analysis artifacts", "",
           "Vendor analysis workflows produce documents, not gate-able findings; "
           "they are attached here and never enter the finding results.", "",
           "| Kind | Producer | Model | Path | Note |", "|---|---|---|---|---|"]
    for a in arts:
        posture = a.get("safeguard_posture")
        note = []
        if a.get("dual_use"):
            note.append("⚠ dual-use — raw/-only, export-excluded")
        if a.get("kind") == "verify-fix":
            # a verify verdict is machine evidence, never a green check — the
            # human decides. crypto gets an explicit cryptographic-review call.
            note.append(f"vendor verdict: {_esc(str(a.get('verdict', '?')))} — "
                        "requires human review (evidence only, never auto-closes)")
        if a.get("kind") == "fix" and a.get("patch", {}).get("review_required"):
            note.append("review_required: " + _esc(", ".join(a["patch"]["review_required"])[:80]))
        if posture == "relaxed":
            note.append("relaxed-safeguard tier")
        out.append(f"| {_enum(a.get('kind'))} | {_cell(a.get('producer'))} | "
                   f"{_cell(a.get('model_id') or '—', 60)} | {_code(a.get('path'), 200)} | "
                   f"{_esc('; '.join(note)) or '—'} |")
    out.append("")
    return out


def _footer(manifest: dict) -> list[str]:
    out = ["## Artifacts", ""]
    reports = manifest.get("reports", []) or []
    dirs = {posixpath.dirname(str(r.get("path") or "")) for r in reports}
    common = dirs.pop() if len(dirs) == 1 else None
    if common:
        out.append(f"Run directory: {_code(common, 400)}")
        out.append("")
    for r in reports:
        path = str(r.get("path") or "")
        shown = posixpath.basename(path) if common else path
        out.append(f"- {_code(shown, 400)} ({_enum(r.get('format'))})")
    out.append("")
    out.append("_Generated by security-council. Findings are clustered by root cause; corroboration is "
               "category-aware (only arms eligible to report a category count); validator verdicts "
               "demote but never hide a finding; crypto findings are never auto-suppressed._")
    out.append("")
    return out


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #


def to_markdown(findings: list[Finding], manifest: dict, *, detail_limit: int | None = 50,
                scores: dict | None = None) -> str:
    """Render the executive summary + findings register + top-N details.

    `manifest` is the run manifest (see manifest.build_manifest); `findings` are
    the merged (post-cluster, post-coverage, optionally validated) findings.
    `scores` maps finding id -> strict-scope fitted score info (R7 (d)-lite:
    post-clamp p, clamps, record id) for unvalidated deterministic singletons.
    """
    ordered = sorted(findings, key=_sort_key)
    out: list[str] = []
    out += _header(manifest, ordered)
    out += _summary(ordered, manifest)
    out += _method(ordered, manifest)
    out += _register(ordered, scores)
    if ordered:
        shown = ordered if detail_limit is None else ordered[:detail_limit]
        out += ["## Findings", ""]
        for i, f in enumerate(shown, 1):
            out += _detail(i, f, scores)
        if len(shown) < len(ordered):
            out.append(f"_{len(ordered) - len(shown)} further finding(s) are listed in the register above "
                       "and carried in full in `findings.json` / `merged.sarif`._")
            out.append("")
    out += _appendix(ordered)
    out += _analysis_artifacts(manifest)
    out += _footer(manifest)
    return "\n".join(out)
