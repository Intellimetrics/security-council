"""Panel synthesis: council verdicts -> Validation + disposition state."""

from __future__ import annotations

import hashlib

from ..model import (
    EvidenceCitation,
    Finding,
    PanelOpinion,
    Validation,
    Verdict,
    _URI_RE,
)
from ..score import _anchor_ranges, _is_anchored
from . import council_client
from .council_client import CouncilResult
from .prompts import build_validation_prompt

FAMILY_BY_PEER = {"claude": "claude", "codex": "codex", "antigravity": "google",
                  "gemini": "google", "qwen": "qwen"}
ROLE_BY_STANCE = {"for": "prosecutor", "against": "defender", "neutral": "adjudicator"}
_LABEL_TO_VERDICT = {"yes": "true_positive", "no": "false_positive", "tradeoff": "uncertain"}


def _citations(evidence: list[dict]) -> tuple[list[EvidenceCitation], int]:
    """Returns (well-formed citations, malformed_count).

    R10: malformed entries used to be dropped silently, which meant junk RAISED
    the pass rate — it shrank the denominator. They now count against it. An
    entry with no `path` at all is prose evidence, not a broken citation, so it
    is neither counted nor penalised.
    """
    out: list[EvidenceCitation] = []
    malformed = 0
    for e in evidence:
        path = e.get("path")
        if path is None:
            continue                      # prose evidence, not a citation claim
        if not path or not _URI_RE.match(str(path)):
            malformed += 1
            continue
        s, en = e.get("start_line"), e.get("end_line")
        if not isinstance(s, int) or not isinstance(en, int) or s < 1 or en < s:
            malformed += 1
            continue
        out.append(EvidenceCitation(path=path, start_line=s, end_line=en,
                                    claim=e.get("text", "")[:300], verified=e.get("verified")))
    return out, malformed


def _refutation_block_reason(op: PanelOpinion, anchors) -> str | None:
    """Why this `false_positive` vote may not carry a refutation — None if it may.

    R10 follow-up: anchoring was originally enforced only through
    `_fully_verified_defender` -> G2, which applies only to findings with a
    deterministic source. That left AGENT-ONLY findings — the cross-file IDOR
    shape this project exists to catch — refutable by peers citing
    `README.md:1-1`. The anchor now gates every refutation, at the panel.
    """
    if op.status != "ok":
        return op.status                      # unevidenced / unreliable
    if not any(_is_anchored(c, anchors) for c in op.citations):
        return "unanchored"
    return None


def _opinion(peer, prompt_sha256: str) -> PanelOpinion:
    role = ROLE_BY_STANCE.get(peer.stance or "", "adjudicator")
    cites, malformed = _citations(peer.evidence)
    verdict = peer.verdict or _LABEL_TO_VERDICT.get(peer.label or "", "uncertain")
    verified = [c for c in cites if c.verified is True]
    denom = len(cites) + malformed
    pass_rate = (len(verified) / denom) if denom else None
    status = "ok"
    if not peer.ok:
        status = "absent"
    elif not cites:
        status = "unevidenced"
    elif pass_rate is not None and pass_rate < 0.67:
        status = "unreliable"
    return PanelOpinion(
        # an UNMAPPED peer is of unknown provenance: bucket it as "unknown" so two
        # of them cannot pass as two independent vendor families. Add a row to
        # FAMILY_BY_PEER when seating a new peer; `participant` still names it.
        role=role, participant=peer.name, family=FAMILY_BY_PEER.get(peer.name, "unknown"),
        prompt_sha256=prompt_sha256, verdict=verdict,
        rationale=(peer.blockers[0] if peer.blockers else ""),
        model_id=peer.model, citations=cites, citation_pass_rate=pass_rate, status=status)


def synthesize_validation(finding: Finding, cr: CouncilResult, *, prompt_sha256: str,
                          extra_opinions: list[PanelOpinion] | None = None) -> Validation:
    panel = [_opinion(p, prompt_sha256) for p in cr.results] + list(extra_opinions or [])
    ok = [op for op in panel if op.status != "absent"]
    # only INDEPENDENT opinions DECIDE the verdict (M-V5): a vendor validate/triage
    # voter is the same family that scanned, so it can never flip a verdict or
    # satisfy the >=2-voice quorum — it is advisory, surfaced but non-deciding.
    deciding = [op for op in ok if op.independent]
    reals = [op for op in deciding if op.verdict == "true_positive"]

    # R10 — refuting is the wrongful-suppression direction, so it is gated harder
    # than confirming, in three ways:
    #  (a) only a FULLY-EVIDENCED opinion may refute. An `unevidenced` peer cited
    #      nothing and an `unreliable` one cited badly; neither is a basis for
    #      taking a finding out of the CI gate. Both still count toward
    #      `true_positive`, which is the fail-safe direction.
    #  (b) refuters must span >= 2 DISTINCT vendor families, so one vendor's blind
    #      spot cannot both produce and confirm a refutation. (FAMILY_BY_PEER maps
    #      antigravity and gemini onto the same "google" family.)
    #  (c) ANY peer arguing false_positive off a fabricated citation forces human
    #      review — previously only the seat holding the defender role did.
    anchors = _anchor_ranges(finding)
    fp_votes = [op for op in deciding if op.verdict == "false_positive"]
    blocked_refuters = [(op, r) for op in fp_votes
                        if (r := _refutation_block_reason(op, anchors)) is not None]
    refuters = [op for op in fp_votes if _refutation_block_reason(op, anchors) is None]
    refuter_families = {op.family for op in refuters}

    # a defender that fabricated a citation is the classic auto-suppression failure
    defender_hallucinated = any(
        op.role == "defender" and any(c.verified is False for c in op.citations) for op in panel)
    refuter_hallucinated = any(
        op.verdict == "false_positive" and any(c.verified is False for c in op.citations)
        for op in panel)

    verdict: Verdict
    if cr.degraded or len(deciding) < 2 or defender_hallucinated or refuter_hallucinated:
        verdict = "needs_human"
    elif len(reals) >= 2 and len(reals) > len(refuters):
        verdict = "true_positive"
    elif len(refuter_families) >= 2 and len(refuters) > len(reals):
        verdict = "false_positive"
    else:
        verdict = "uncertain"

    denom = max(1, len(deciding))
    conf = {"true_positive": len(reals) / denom,
            "false_positive": len(refuters) / denom}.get(verdict, 0.5)
    all_cites = [c for op in panel for c in op.citations]
    advisory = [op for op in ok if not op.independent]
    evidence_check = {
        "citations_total": len(all_cites),
        "citations_verified": sum(1 for c in all_cites if c.verified is True),
        "hallucinated": sum(1 for c in all_cites if c.verified is False),
        "defender_hallucinated": defender_hallucinated,
        "refuter_hallucinated": refuter_hallucinated,
        "refuter_families": sorted(refuter_families),
    }
    if blocked_refuters:
        # say out loud that someone voted to drop this finding and was not counted
        evidence_check["refutation_blocked"] = {
            "voters": [op.participant for op, _ in blocked_refuters],
            "statuses": [reason for _, reason in blocked_refuters],
        }
    if advisory:
        # record what the vendor voters said and whether they DISAGREE — a signal
        # for humans, not an input to the automated verdict
        evidence_check["vendor_advisory"] = {
            "voters": [op.participant for op in advisory],
            "verdicts": [op.verdict for op in advisory],
            "disagrees_with_panel": any(op.verdict != verdict for op in advisory
                                        if op.verdict in ("true_positive", "false_positive")),
        }
    # R10: `no_cross_file_navigation` was READ by score.py and assigned nowhere,
    # so the clamp advertised in docs/safety-model.md had never once fired.
    # Deterministic signal for it: the finding spans more than one file, but no
    # panel opinion cited more than one — the panel never followed the flow across
    # files, which is the published 96% -> 44% triage-accuracy failure mode.
    finding_files = {loc.uri for loc in finding.locations} | {
        st.location.uri for st in finding.data_flow}
    max_files_cited = max((len({c.path for c in op.citations}) for op in ok), default=0)
    no_xfile = len(finding_files) > 1 and max_files_cited <= 1

    return Validation(verdict=verdict, confidence=round(conf, 3), panel=panel,
                      evidence_check=evidence_check, calibration="prior",
                      no_cross_file_navigation=no_xfile)


_VENDOR_VERDICT = {"yes": "true_positive", "true_positive": "true_positive", "confirmed": "true_positive",
                   "no": "false_positive", "false_positive": "false_positive", "fp": "false_positive",
                   "uncertain": "uncertain", "tradeoff": "uncertain"}


def vendor_opinion(v: dict, prompt_sha256: str) -> PanelOpinion:
    """A vendor validate/triage verdict as a NON-INDEPENDENT, advisory panel
    opinion (weight 0, cannot decide the verdict)."""
    verdict = _VENDOR_VERDICT.get(str(v.get("verdict", "")).lower(), "uncertain")
    # a voter that could not run is recorded as "absent": it is kept in the panel
    # (so the report can say the vendor voter was unavailable) but is filtered out
    # of `ok`, so it never counts toward evidence or the advisory disagreement flag
    status = str(v.get("status") or "ok")
    return PanelOpinion(role="vendor", participant=v.get("participant", "vendor"),
                        family=v.get("family", "vendor"), prompt_sha256=prompt_sha256,
                        verdict=verdict, rationale=str(v.get("rationale", ""))[:300],
                        model_id=v.get("model_id"), status=status, independent=False, weight=0.0)


def make_vendor_runner(repo_root, *, family: str = "codex", proc_run=None,
                       effort: str = "low"):
    """A runner(finding) -> [vendor opinion dict] that shells out to the vendor
    `validate` skill. `proc_run` is injectable for offline tests; the default is
    the real subprocess runner (live invocation needs vendor spend).

    Command contract verified live 2026-08-25 against codex-security 0.1.16/0.1.20:
    `validate` takes finding text (or a file) positionally and **rejects
    `--format json`** ("validate does not support noninteractive JSON output"),
    so the verdict is read from prose. `--effort` defaults to `xhigh` upstream,
    which is billed per finding — we pass `low` unless told otherwise.
    """
    from .. import proc as _proc
    run = proc_run or _proc.run_command

    def _runner(finding: Finding) -> list[dict]:
        title = getattr(finding, "title", "") or ""
        cmd = (["codex-security", "validate", title, "--effort", effort] if family == "codex"
               else ["claude", "-p", f"/claude-security triage-finding: {title}",
                     "--output-format", "json"])
        r = run(cmd, timeout=600, cwd=str(repo_root))
        if not getattr(r, "ok", False):
            # never silently drop the voter: a vendor CLI that fails to run is
            # recorded as absent (weight 0, filtered from the vote) so the run
            # shows the opinion was sought and did not arrive
            why = (getattr(r, "stderr", "") or getattr(r, "stdout", "") or "").strip()
            return [{"participant": f"{family}-validate", "family": family,
                     "verdict": "uncertain", "status": "absent",
                     "rationale": f"vendor validate unavailable: {why[:200]}"}]
        return [{"participant": f"{family}-validate", "family": family,
                 "verdict": _scan_verdict(r.stdout), "rationale": (r.stdout or "")[:300]}]
    return _runner


def _scan_verdict(text: str) -> str:
    t = (text or "").lower()
    if "false positive" in t or "not exploitable" in t or "\"false_positive\"" in t:
        return "false_positive"
    if "true positive" in t or "confirmed" in t or "\"true_positive\"" in t:
        return "true_positive"
    return "uncertain"


def _state_for(finding: Finding, val: Validation) -> str:
    if val.verdict == "true_positive":
        corr = finding.corroboration
        strong = corr.independent_family_count >= 2 or bool(corr.deterministic_sources)
        return "validated" if strong else "likely"
    return {"false_positive": "refuted", "uncertain": "disputed",
            "needs_human": "needs_human"}[val.verdict]


def validate_finding(finding: Finding, *, repo_root, runner=council_client.run_council,
                     mode: str = "consensus", max_cost_usd: float | None = 0.5,
                     timeout: int = 600, vendor_runner=None) -> Finding:
    prompt = build_validation_prompt(finding)
    psha = hashlib.sha256(prompt.encode()).hexdigest()
    cr = runner(prompt, cwd=repo_root, mode=mode, max_cost_usd=max_cost_usd, timeout=timeout)
    extra = None
    if vendor_runner is not None:
        extra = [vendor_opinion(v, psha) for v in (vendor_runner(finding) or [])]
    val = synthesize_validation(finding, cr, prompt_sha256=psha, extra_opinions=extra)
    finding.validation = val
    finding.disposition.state = _state_for(finding, val)
    # lifecycle stays "open": v1 auto-demotes (refuted -> underReview in SARIF) but never
    # auto-closes/suppresses. Suppression is a later, policy-gated, shadow-mode decision.
    return finding


# Families whose findings are deterministic (from a scanner/CVE feed) and gain
# nothing from the SAST-shaped code-reachability panel — skipped by default.
SKIP_VALIDATION_FAMILIES = frozenset({"supply_chain"})


def validate_findings(findings: list[Finding], *, repo_root, runner=council_client.run_council,
                      max_findings: int | None = None,
                      skip_families: frozenset = SKIP_VALIDATION_FAMILIES, **kw) -> list[Finding]:
    from ..model import CLOSED_LIFECYCLES
    eligible = [f for f in findings if f.taxonomy.cwe_family not in skip_families
                and f.disposition.lifecycle not in CLOSED_LIFECYCLES]
    ranked = sorted(eligible, key=lambda f: f.severity.security_severity, reverse=True)
    todo = ranked[:max_findings] if max_findings else ranked
    for f in todo:
        validate_finding(f, repo_root=repo_root, runner=runner, **kw)
    return findings
