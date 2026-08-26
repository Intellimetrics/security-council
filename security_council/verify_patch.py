"""Deterministic verify-fix (R11 Q4): does a patch make the finding go away?

Asking a model whether a patch worked is worth little — least of all when the
patch came from the same vendor. The verification that costs nothing and
proves something is deterministic:

1. the ORCHESTRATOR applies the patch to a fresh scratch copy of the target
   (`patches.apply_patch`; never an agent, never the user's tree);
2. the deterministic scanner arms that reported the finding
   (`finding.corroboration.deterministic_sources` — semgrep, gitleaks,
   osv-scanner) are re-run against the patched copy;
3. the finding must DISAPPEAR, identified by the same fingerprint tiers the
   baseline delta uses (`decisions.MATCH_TIERS`: root cause, then context
   hash, then path+CWE+sink).

Verdicts — machine EVIDENCE, never a decision:

- ``fixed``      absent from the patched-copy scan of EVERY scanner that had
                 reported it, and each of those scans has coverage verdict
                 ``verified`` (R12 model). A scanner that examined less than
                 the full copy cannot vouch for an absence.
- ``not_fixed``  still reported by at least one of them — or the same rule
                 fired at a NEW place in the same file that was not in the
                 run (a "fix" that moved the sink is not a fix).
- ``unproven``   nothing could vouch: the finding had no deterministic
                 source, an arm was unavailable or failed, coverage was not
                 verified, or the patch did not apply.

Hard rules kept from R6/R11: the verdict is bound to ``patch_sha256`` +
``base_commit``; it is recorded via ``DecisionStore.record_verify_evidence``
with ``kind: deterministic_verify_fix`` and ``decided_by: machine``; it can
never close a finding, change a disposition, feed the score history term (L1
— ``history_counts`` ignores it) or become a panel vote (L3). A model may
EXPLAIN a result later; it never decides one. No network, no vendor CLI and
no fence are involved beyond what the scanner arms themselves need.
"""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from pathlib import Path

from . import decisions as decisions_mod, patches as _patches
from .arms.base import Arm, ArmResult
from .artifacts import Artifact, artifact_id
from .model import Finding
from .normalize import coverage
from .workspace import prepare_workspace

FIXED, NOT_FIXED, UNPROVEN = "fixed", "not_fixed", "unproven"
PRODUCER = "deterministic-verify-fix"
METHOD = "deterministic"
EVIDENCE_KIND = "deterministic_verify_fix"
# where the patched-copy scanner output lands inside the run dir
VERIFY_SUBDIR = "verify-patch"


@dataclass
class SourceCheck:
    """One deterministic scanner's look at the patched copy, for one finding."""
    arm: str
    tool_version: str | None = None
    coverage: str = coverage.NONE           # coverage verdict of the patched-copy scan
    present: bool | None = None             # None: the arm could not look
    match_tier: str | None = None           # how the finding was re-identified
    moved_to: list[str] = field(default_factory=list)   # same rule/family, same file, new
    error: str = ""


@dataclass
class FindingVerdict:
    finding_id: str
    root_cause: str
    title: str
    uri: str
    severity: str
    verdict: str
    reasons: list[str] = field(default_factory=list)
    sources: list[SourceCheck] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class PatchVerification:
    patch: str                              # the patch file as named by the caller
    patch_sha256: str
    base_commit: str | None
    applied: bool
    apply_error: str
    files: list[str]                        # files the patch touches
    review_required: list[str]              # validator flags (tests/CI/lockfiles ...)
    refused: list[str]                      # validator refusals (patch not applied)
    arms: list[dict]                        # each scanner run on the patched copy
    results: list[FindingVerdict]
    new_findings: int = 0                   # on the patched copy, not in the run (any file)
    producer: str = PRODUCER
    method: str = METHOD

    def counts(self) -> dict[str, int]:
        out = {FIXED: 0, NOT_FIXED: 0, UNPROVEN: 0}
        for r in self.results:
            out[r.verdict] += 1
        return out

    def to_dict(self) -> dict:
        d = asdict(self)
        d["counts"] = self.counts()
        return d


def sha256_of(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


# --------------------------------------------------------------------------- #
# identity: the same three tiers the baseline delta uses
# --------------------------------------------------------------------------- #

def _find(f: Finding, candidates: list[Finding]) -> tuple[str | None, Finding | None]:
    """(tier, candidate) for the strongest-tier match of `f` among `candidates`."""
    for tier in decisions_mod.MATCH_TIERS:
        want = getattr(f.fingerprints, tier)
        for c in candidates:
            if want and getattr(c.fingerprints, tier) == want:
                return tier, c
    return None, None


def _primary_uri(f: Finding) -> str:
    return f.locations[0].uri if f.locations else ""


def _label(c: Finding) -> str:
    loc = c.locations[0] if c.locations else None
    where = f"{loc.uri}:{loc.start_line}" if loc else "?"
    return f"{c.rule.source_rule_id or c.rule.id} at {where}"


def _unexplained(patched: list[Finding], run_findings: list[Finding]) -> list[Finding]:
    """Findings on the patched copy that no finding of the ORIGINAL run
    identifies (by any tier) — i.e. what the patch introduced or moved."""
    return [c for c in patched if _find(c, run_findings)[0] is None]


def _moved(f: Finding, unexplained: list[Finding]) -> list[str]:
    """New findings in the SAME file that fire the same rule (or the same CWE
    family): the sink moved rather than went away. Fail-safe: reported as
    still present."""
    uri = _primary_uri(f)
    out = []
    for c in unexplained:
        if _primary_uri(c) != uri:
            continue
        same_rule = (f.rule.source_rule_id and c.rule.source_rule_id == f.rule.source_rule_id)
        if same_rule or c.taxonomy.cwe_family == f.taxonomy.cwe_family:
            out.append(_label(c))
    return out


def _verdict_for(f: Finding, results: dict[str, ArmResult],
                 unexplained_by_arm: dict[str, list[Finding]]) -> FindingVerdict:
    fv = FindingVerdict(finding_id=f.id, root_cause=f.fingerprints.root_cause, title=f.title,
                        uri=_primary_uri(f), severity=f.severity.label, verdict=UNPROVEN)
    sources = sorted(set(f.corroboration.deterministic_sources))
    if not sources:
        fv.reasons.append("no deterministic scanner reported this finding, so no scanner "
                          "can vouch that it is gone (an agent-only finding needs a human)")
        return fv
    present_any = False
    all_verified_absent = True
    for s in sources:
        res = results.get(s)
        if res is None:
            fv.sources.append(SourceCheck(arm=s, error="not run on the patched copy"))
            fv.reasons.append(f"{s}: not run on the patched copy")
            all_verified_absent = False
            continue
        cv = coverage.coverage_verdict(res)
        chk = SourceCheck(arm=s, tool_version=res.tool_version, coverage=cv)
        if not res.ok:
            chk.error = (res.error or "failed")[:200]
            fv.reasons.append(f"{s}: failed on the patched copy ({chk.error[:120]})")
            all_verified_absent = False
        tier, hit = _find(f, res.findings)
        if hit is not None:
            chk.present, chk.match_tier = True, tier
            present_any = True
            fv.reasons.append(f"{s}: still reports it (matched by {tier})")
        else:
            chk.present = False
            chk.moved_to = _moved(f, unexplained_by_arm.get(s, []))
            if chk.moved_to:
                present_any = True
                fv.reasons.append(f"{s}: gone as fingerprinted, but a new finding of the same "
                                  f"rule/family appeared in {fv.uri} that was not in this run "
                                  f"({'; '.join(chk.moved_to[:3])}) — the sink moved, it was "
                                  "not removed")
            elif res.ok and cv != coverage.VERIFIED:
                all_verified_absent = False
                fv.reasons.append(f"{s}: absent, but its coverage of the patched copy is "
                                  f"'{cv}', not 'verified' — an absence from an incomplete "
                                  "scan proves nothing")
            elif res.ok:
                fv.reasons.append(f"{s}: absent from a verified scan of the patched copy")
        fv.sources.append(chk)
    if present_any:
        fv.verdict = NOT_FIXED
    elif all_verified_absent:
        fv.verdict = FIXED
    else:
        fv.verdict = UNPROVEN
    return fv


# --------------------------------------------------------------------------- #
# the lane
# --------------------------------------------------------------------------- #

def _run_arm(arm: Arm, root: Path, out_dir: Path, run_id: str, collected_at: str) -> ArmResult:
    # same contract as orchestrator._safe_run (imported lazily: the
    # orchestrator imports this module)
    from .orchestrator import _safe_run
    return _safe_run(arm, root, out_dir, run_id, collected_at)


def select_findings(findings: list[Finding], *, files: list[str],
                    finding_ids: list[str] | None) -> tuple[list[Finding], list[str]]:
    """Which open findings a patch is checked against.

    With explicit ids: those (exact id, or a unique prefix of at least 6
    characters — the summary prints ids in full). Without: every open finding
    whose primary location is in a file the patch touches. Returns
    (findings, unknown_ids)."""
    open_ = [f for f in findings
             if f.disposition.lifecycle in ("open", "reopened")
             and f.disposition.state != "refuted"]
    if finding_ids:
        chosen, unknown = [], []
        for want in finding_ids:
            exact = [f for f in open_ if f.id == want]
            pref = ([f for f in open_ if len(want) >= 6 and f.id.startswith(want)]
                    if not exact else exact)
            if len(pref) == 1:
                if pref[0] not in chosen:
                    chosen.append(pref[0])
            else:
                unknown.append(want)
        return chosen, unknown
    touched = set(files)
    return [f for f in open_ if _primary_uri(f) in touched], []


def verify_patch(target: Path, patch_path: Path, findings: list[Finding],
                 run_findings: list[Finding], *, arms: list[Arm], out_dir: Path,
                 run_id: str, collected_at: str, base_commit: str | None,
                 patch_label: str | None = None) -> PatchVerification:
    """Apply `patch_path` to a scratch copy of `target`, re-run the deterministic
    scanners that reported each of `findings`, and say whether each is gone.

    `run_findings` are ALL merged findings of the run (the pre-patch picture at
    the same commit), so a finding that merely moved can be told from one that
    was already there. `arms` are the run's arm objects; only scanner-kind arms
    named by the findings' deterministic sources are re-run."""
    target = Path(target).resolve()
    patch_path = Path(patch_path)
    sha = sha256_of(patch_path)
    text = patch_path.read_text(encoding="utf-8", errors="replace")
    report = _patches.validate_patch(text)
    pv = PatchVerification(patch=patch_label or patch_path.name, patch_sha256=sha,
                           base_commit=base_commit, applied=False, apply_error="",
                           files=list(report.files), review_required=list(report.review_required),
                           refused=list(report.refused), arms=[], results=[])
    if report.refused:
        pv.apply_error = "patch refused by the validator: " + ", ".join(report.refused)
        pv.results = [_unproven(f, pv.apply_error) for f in findings]
        return pv
    if not findings:
        pv.apply_error = "nothing to verify (no finding selected), patch not applied"
        return pv
    scanner_arms = {a.name: a for a in arms if getattr(a, "kind", "") == "scanner"}
    needed = sorted({s for f in findings for s in f.corroboration.deterministic_sources})
    ws = prepare_workspace(target, mode="copy")
    results: dict[str, ArmResult] = {}
    try:
        pv.applied, pv.apply_error = _patches.apply_patch(ws.root, patch_path)
        if not pv.applied:
            pv.results = [_unproven(f, f"patch did not apply cleanly: {pv.apply_error}")
                          for f in findings]
            return pv
        vdir = Path(out_dir) / VERIFY_SUBDIR
        vdir.mkdir(parents=True, exist_ok=True)
        for name in needed:
            arm = scanner_arms.get(name)
            if arm is None:
                continue
            res = _run_arm(arm, ws.root, vdir, run_id, collected_at)
            results[name] = res
            pv.arms.append({"name": res.name, "ok": res.ok, "tool_version": res.tool_version,
                            "coverage_verdict": coverage.coverage_verdict(res),
                            "findings": len(res.findings), "error": res.error or None,
                            "elapsed_seconds": round(res.elapsed_seconds, 2)})
    finally:
        ws.cleanup()
    unexplained = {name: _unexplained(res.findings, run_findings) for name, res in results.items()}
    pv.new_findings = sum(len(v) for v in unexplained.values())
    pv.results = [_verdict_for(f, results, unexplained) for f in findings]
    return pv


def _unproven(f: Finding, reason: str) -> FindingVerdict:
    return FindingVerdict(finding_id=f.id, root_cause=f.fingerprints.root_cause, title=f.title,
                          uri=_primary_uri(f), severity=f.severity.label, verdict=UNPROVEN,
                          reasons=[reason])


# --------------------------------------------------------------------------- #
# evidence: manifest artifacts + decision-store records (machine, non-closing)
# --------------------------------------------------------------------------- #

def producer_label(pv: PatchVerification) -> str:
    """`semgrep 1.2.3, gitleaks 8.18.0` — the scanners that vouched, with versions."""
    parts = [f"{a['name']} {a['tool_version']}" if a.get("tool_version") else a["name"]
             for a in pv.arms]
    return ", ".join(parts) or PRODUCER


def evidence_artifacts(pv: PatchVerification, *, run_id: str, collected_at: str,
                       fix_family: str | None = None) -> list[dict]:
    """One `verify-fix` evidence artifact per verified finding (manifest
    `artifacts`). `fix_family` names the vendor that produced the patch, if a
    vendor did; the verifier is a scanner, so it is independent of any patch
    producer by construction."""
    out = []
    for r in pv.results:
        rel = f"verify:{r.finding_id}:{pv.patch_sha256[:12]}"
        art = Artifact(
            id=artifact_id(kind="verify-fix", producer=PRODUCER, path=rel, run_id=run_id),
            kind="verify-fix", title=f"Patch verification: {r.verdict} for {r.finding_id}",
            path=rel, producer=PRODUCER, family=METHOD, dual_use=False, export_excluded=False,
            created_at=collected_at, model_id=None, safeguard_posture="default",
            format="evidence", related_finding_ids=[r.finding_id])
        out.append({**art.to_dict(), "verdict": r.verdict, "method": METHOD,
                    "patch": pv.patch, "patch_sha256": pv.patch_sha256,
                    "base_commit": pv.base_commit, "checked_by": producer_label(pv),
                    "reasons": list(r.reasons), "sources": [asdict(s) for s in r.sources],
                    "note": "; ".join(r.reasons), "fix_family": fix_family,
                    "decided_by": "machine", "independent": True, "non_closing": True})
    return out


def record_evidence(store, pv: PatchVerification, findings: list[Finding], *,
                    now_iso: str) -> list[dict]:
    """Persist each verdict as `deterministic_verify_fix` machine evidence on
    the finding's root-cause record. Never a disposition; never counted by
    `history_counts` (L1)."""
    by_id = {f.id: f for f in findings}
    events = []
    for r in pv.results:
        f = by_id.get(r.finding_id)
        if f is None:
            continue
        events.append(store.record_verify_evidence(
            root_cause=f.fingerprints.root_cause, finding_id=f.id, verdict=r.verdict,
            patch_sha256=pv.patch_sha256, base_commit=pv.base_commit,
            producer=producer_label(pv), now_iso=now_iso, model=None,
            note="; ".join(r.reasons), title=f.title,
            context_hash=f.fingerprints.context_hash, kind=EVIDENCE_KIND,
            detail={"patch": pv.patch, "files": pv.files,
                    "sources": [asdict(s) for s in r.sources]}))
    return events
