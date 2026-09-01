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
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

from . import decisions as decisions_mod, patches as _patches, proc
from .arms.base import Arm, ArmResult
from .artifacts import Artifact, artifact_id
from .jsonio import finding_from_dict
from .model import Finding, assert_invariants
from .normalize import coverage
from .workspace import git_info, prepare_workspace

FIXED, NOT_FIXED, UNPROVEN = "fixed", "not_fixed", "unproven"
PRODUCER = "deterministic-verify-fix"
METHOD = "deterministic"
EVIDENCE_KIND = "deterministic_verify_fix"
# where the patched-copy scanner output lands inside the run dir
VERIFY_SUBDIR = "verify-patch"
CONTROL_SUBDIR = "verify-control"

# Graded `unproven (<reason>)` tokens for `--against RUN_DIR` (R19 A2). Every
# precondition fails CLOSED to one of these — never a usage error, a crash, or
# a `fixed`.
R_BASE_MISMATCH = "base_mismatch"
R_TARGET_DIRTY = "target_dirty"
R_AGAINST_SCOPE = "against_scope_not_full"
R_AGAINST_COVERAGE = "against_coverage_not_verified"
R_AGAINST_TRACKED = "against_run_dir_tracked"
R_AGAINST_INCONSISTENT = "against_manifest_inconsistent"
R_CONTROL_NOT_REPRODUCED = "control_not_reproduced"
R_CONTROL_ARM_UNAVAILABLE = "control_arm_unavailable"
R_PATCH_REFUSED = "patch_refused"
R_PATCH_NOT_APPLIED = "patch_not_applied"


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
    # R19 A2: `--against RUN_DIR` extends the lane to judge a patch against an
    # OLD run's finding population. `mode` is "current" (re-run the CURRENT
    # tree) or "against". These stay empty/None in the "current" mode so its
    # manifest shape is unchanged.
    mode: str = "current"
    against: dict | None = None             # old-run identity binding (id/commit/manifest sha256)
    precondition: dict | None = None        # {reason, detail} when a global precondition fails
    control_arms: list[dict] = field(default_factory=list)   # scanners on the UNPATCHED current tree

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


def _ruleset_of(arm) -> str | None:
    """The ruleset identity of a scanner arm, so drift between the control and
    patched sides (and against the old run) is VISIBLE in the evidence. semgrep
    pins a named ruleset; gitleaks/osv-scanner run a config WE ship."""
    spec = getattr(arm, "spec", None)
    if spec is None:
        return None
    if getattr(arm, "name", "") == "semgrep":
        from .arms.scanner import SEMGREP_RULESET
        return SEMGREP_RULESET
    return getattr(spec, "config_file", None)


def _arm_meta(res: ArmResult, arm=None) -> dict:
    """One scanner's run recorded for the evidence binding (versions + ruleset +
    coverage), used for BOTH the control and patched passes."""
    return {"name": res.name, "ok": res.ok, "tool_version": res.tool_version,
            "ruleset": _ruleset_of(arm) if arm is not None else None,
            "coverage_verdict": coverage.coverage_verdict(res),
            "findings": len(res.findings), "error": res.error or None,
            "elapsed_seconds": round(res.elapsed_seconds, 2)}


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
                 unexplained_by_arm: dict[str, list[Finding]],
                 deleted: set[str] | None = None) -> FindingVerdict:
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
        if deleted and fv.uri in deleted:
            # R14: honest by the scanner's lights (nothing left to report), but a
            # reviewer must SEE that the fix was a deletion, not a repair
            fv.reasons.append(f"note: the patch REMOVED {fv.uri} — the scanner sees nothing "
                              "because there is nothing to see; confirm that deleting the "
                              "file is the intended fix, not the feature going with it")
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
        deleted = ({u for u in {_primary_uri(f) for f in findings} if u and not (ws.root / u).exists()}
                   if pv.applied else set())
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
            pv.arms.append(_arm_meta(res, arm))
    finally:
        ws.cleanup()
    unexplained = {name: _unexplained(res.findings, run_findings) for name, res in results.items()}
    pv.new_findings = sum(len(v) for v in unexplained.values())
    pv.results = [_verdict_for(f, results, unexplained, deleted) for f in findings]
    return pv


def _unproven(f: Finding, reason: str) -> FindingVerdict:
    return FindingVerdict(finding_id=f.id, root_cause=f.fingerprints.root_cause, title=f.title,
                          uri=_primary_uri(f), severity=f.severity.label, verdict=UNPROVEN,
                          reasons=[reason])


# --------------------------------------------------------------------------- #
# A2: `--verify-patch --against RUN_DIR` — judge a patch against an OLD run's
# finding population, guarded by a control run of the CURRENT scanners so that
# scanner/ruleset drift cannot masquerade as a fix (R19 council).
# --------------------------------------------------------------------------- #

def _load_against(run_dir: Path) -> tuple[dict | None, list[Finding], str | None, str | None]:
    """Load and INTERNALLY VALIDATE an against-run dir. Returns
    (manifest, findings, manifest_sha256, error). `error` is a graded-unproven
    reason (`against_manifest_inconsistent`) when the run is untrustworthy; the
    manifest sha256 is recorded either way so tampering stays visible (run dirs
    are unsigned — the same trust class as the pre-R9 store)."""
    valid = {coverage.VERIFIED, coverage.PARTIAL, coverage.NONE}
    if not run_dir.is_dir():
        return None, [], None, f"{run_dir} is not a directory"
    mf, fj = run_dir / "manifest.json", run_dir / "findings.json"
    mf_sha = sha256_of(mf) if mf.is_file() else None
    if not mf.is_file() or not fj.is_file():
        return None, [], mf_sha, "the against-run is missing manifest.json or findings.json"
    try:
        manifest = json.loads(mf.read_text())
        raw = json.loads(fj.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        return None, [], mf_sha, f"could not parse the against-run: {exc}"
    if not isinstance(manifest, dict) or not isinstance(raw, list):
        return None, [], mf_sha, "manifest.json must be an object and findings.json an array"
    findings: list[Finding] = []
    for d in raw:
        if not isinstance(d, dict):
            return manifest, [], mf_sha, "a findings.json row is not an object"
        try:
            f = finding_from_dict(d)
            assert_invariants(f)                     # model boundary: external artifact
        except Exception as exc:                     # noqa: BLE001 - any parse/invariant failure
            return manifest, [], mf_sha, f"a findings.json row failed model validation: {exc}"
        findings.append(f)
    if not isinstance(manifest.get("run_id"), str) or not manifest.get("run_id"):
        return manifest, findings, mf_sha, "manifest.json carries no run_id"
    if not isinstance(manifest.get("target"), dict) or not isinstance(manifest.get("arms"), list):
        return manifest, findings, mf_sha, "manifest.json target/arms are malformed"
    total = (manifest.get("counts") or {}).get("total")
    if total != len(findings):
        return manifest, findings, mf_sha, (f"manifest counts.total={total} != {len(findings)} "
                                            "findings on disk — the run dir was tampered with")
    for a in manifest["arms"]:
        cv = a.get("coverage_verdict") if isinstance(a, dict) else "?"
        if cv is not None and cv not in valid:
            return manifest, findings, mf_sha, (f"arm {a.get('name')!r} has an invalid coverage "
                                                f"verdict {cv!r}")
    return manifest, findings, mf_sha, None


def _run_dir_has_tracked_files(run_dir: Path) -> bool:
    """True if the (SYMLINK-RESOLVED) run dir holds git-tracked files — a run
    dir committed into the repo under scan (R14a-S3/R17: a hostile repo commits
    a fake run dir to be trusted as evidence). Legit runs live under the
    gitignored `.security-council/`, so they are never tracked. Fails CLOSED:
    if tracking cannot be established, the dir is refused."""
    top = proc.run_command(["git", "-C", str(run_dir), "rev-parse", "--show-toplevel"], timeout=15)
    if not top.ok or not top.stdout.strip():
        return False                        # not inside any git repo -> untracked, legit
    toplevel = top.stdout.strip()
    ls = proc.run_command(["git", "-C", toplevel, "ls-files", "-z", "--", str(run_dir)], timeout=30)
    if not ls.ok:
        return True                         # cannot list -> fail closed
    return bool(ls.stdout.replace("\x00", "").strip())


def _run_needed(target: Path, scanner_arms: dict, needed: list[str], out_dir: Path, subdir: str,
                *, run_id: str, collected_at: str, patch_path: Path | None = None,
                deleted_candidates: frozenset[str] = frozenset()
                ) -> tuple[dict, list[dict], bool, str, set[str]]:
    """Run `needed` scanners on a fresh scratch copy of `target` — unpatched
    (control) or with `patch_path` applied — into `out_dir/subdir`. Returns
    (results, arm_metas, applied, apply_error, deleted)."""
    results: dict[str, ArmResult] = {}
    metas: list[dict] = []
    applied, apply_error, deleted = (patch_path is None), "", set()
    ws = prepare_workspace(target, mode="copy")
    try:
        if patch_path is not None:
            applied, apply_error = _patches.apply_patch(ws.root, patch_path)
            if not applied:
                return results, metas, applied, apply_error, deleted
            deleted = {u for u in deleted_candidates if u and not (ws.root / u).exists()}
        vdir = Path(out_dir) / subdir
        vdir.mkdir(parents=True, exist_ok=True)
        for name in needed:
            arm = scanner_arms.get(name)
            if arm is None:
                continue
            res = _run_arm(arm, ws.root, vdir, run_id, collected_at)
            results[name] = res
            metas.append(_arm_meta(res, arm))
    finally:
        ws.cleanup()
    return results, metas, applied, apply_error, deleted


def _verdict_against(f: Finding, control_results: dict[str, ArmResult],
                     patched_results: dict[str, ArmResult],
                     unexplained_by_arm: dict[str, list[Finding]],
                     against_coverage: dict[str, str], deleted: set[str]) -> FindingVerdict:
    """The against-mode verdict: two extra fail-closed gates in front of the
    same deterministic patched-copy judgment the current-tree lane uses."""
    sources = sorted(set(f.corroboration.deterministic_sources))
    if not sources:
        return _unproven(f, "no deterministic scanner reported this finding, so none can vouch "
                            "that it is gone (an agent-only finding needs a human)")
    # (a) the OLD run must have covered these scanners fully; an absence judged
    # against a partially-covered old population is not evidence
    bad = [s for s in sources if against_coverage.get(s) != coverage.VERIFIED]
    if bad:
        return _unproven(f, f"{R_AGAINST_COVERAGE}: the against-run's coverage for "
                            f"{', '.join(bad)} was not 'verified'; that old run examined less "
                            "than the full tree, so it is not a whole-tree pre-patch baseline")
    # (b) CONTROL: the finding must still reproduce on the UNPATCHED current tree
    # with the CURRENT scanners — otherwise a scanner/ruleset drift, not the
    # patch, could be what made it 'disappear'
    reproduced = any_ran = False
    for s in sources:
        cres = control_results.get(s)
        if cres is not None and cres.ok:
            any_ran = True
            if _find(f, cres.findings)[0] is not None:
                reproduced = True
    if not reproduced:
        if any_ran:
            return _unproven(f, f"{R_CONTROL_NOT_REPRODUCED}: the current scanners do not report "
                                "this finding on the UNPATCHED tree, so its absence on the "
                                "patched tree is scanner/ruleset drift, not a proven fix")
        return _unproven(f, f"{R_CONTROL_ARM_UNAVAILABLE}: no vouching scanner could run on the "
                            "control (unpatched) tree, so nothing establishes the finding still "
                            "exists to be fixed")
    # (c) the patched judgment is the SAME logic as the current-tree lane, with
    # the CONTROL population as the moved-sink baseline
    fv = _verdict_for(f, patched_results, unexplained_by_arm, deleted)
    fv.reasons.insert(0, "control: the current scanners reproduce this finding on the unpatched "
                         "tree, so the patched result is attributable to the patch")
    return fv


def verify_patch_against(target: Path, patch_path: Path, against_run_dir: Path, *,
                         arms: list[Arm], out_dir: Path, run_id: str, collected_at: str,
                         finding_ids: list[str] | None = None,
                         patch_label: str | None = None) -> PatchVerification:
    """Judge `patch_path` against the finding population of an OLD run
    (`against_run_dir`) at the SAME commit, instead of a fresh full scan.

    Every precondition fails CLOSED to a graded ``unproven (<reason>)`` verdict
    — never a usage error, a crash, or a ``fixed``. A control run of the CURRENT
    scanners on the UNPATCHED tree confirms the finding still reproduces before
    any patched absence can count."""
    target = Path(target).resolve()
    against_run_dir = Path(against_run_dir).resolve()      # symlink-RESOLVED
    patch_path = Path(patch_path)
    sha = sha256_of(patch_path)
    report = _patches.validate_patch(patch_path.read_text(encoding="utf-8", errors="replace"))

    manifest, findings, mf_sha, load_err = _load_against(against_run_dir)
    against = {"run_id": (manifest or {}).get("run_id"), "run_dir": str(against_run_dir),
               "base_commit": ((manifest or {}).get("target") or {}).get("git_commit"),
               "manifest_sha256": mf_sha, "scan_scope": (manifest or {}).get("scan_scope"),
               "coverage": {}, "unknown_ids": []}
    cur = git_info(target)
    pv = PatchVerification(patch=patch_label or patch_path.name, patch_sha256=sha,
                           base_commit=cur.get("git_commit"), applied=False, apply_error="",
                           files=list(report.files), review_required=list(report.review_required),
                           refused=list(report.refused), arms=[], results=[],
                           mode="against", against=against, control_arms=[])

    # unreadable run dir: cannot even SELECT findings -> stated precondition, no verdicts
    if load_err is not None and not findings:
        pv.precondition = {"reason": R_AGAINST_INCONSISTENT, "detail": load_err}
        pv.apply_error = f"{R_AGAINST_INCONSISTENT}: {load_err}"
        return pv

    chosen, unknown = select_findings(findings, files=report.files, finding_ids=finding_ids)
    against["unknown_ids"] = unknown

    def _all_unproven(token: str, detail: str) -> PatchVerification:
        pv.precondition = {"reason": token, "detail": detail}
        pv.apply_error = f"{token}: {detail}"
        pv.results = [_unproven(f, f"{token}: {detail}") for f in chosen]
        return pv

    # global preconditions, in priority order (any failure -> all chosen unproven).
    # The committed-run-dir refusal is a HOSTILE-ARTIFACT check, so it comes
    # before base/dirty/scope: a run dir committed into the repo under scan is
    # untrustworthy regardless of what commit it claims.
    if load_err is not None:
        return _all_unproven(R_AGAINST_INCONSISTENT, load_err)
    if report.refused:
        return _all_unproven(R_PATCH_REFUSED,
                             "patch refused by the validator: " + ", ".join(report.refused))
    if _run_dir_has_tracked_files(against_run_dir):
        return _all_unproven(R_AGAINST_TRACKED, f"{against_run_dir} contains git-tracked files — "
                             "a run dir committed into the repo under scan is refused")
    if not cur.get("git_commit") or against["base_commit"] != cur.get("git_commit"):
        return _all_unproven(R_BASE_MISMATCH, f"against-run base {against['base_commit']!r} != "
                             f"current HEAD {cur.get('git_commit')!r} (a rebase or a different "
                             "commit invalidates the old finding population)")
    if cur.get("dirty") is not False:
        return _all_unproven(R_TARGET_DIRTY, "the current target tree is dirty or its git status "
                             "is unknown (the .security-council state dir is exempt)")
    scope = (against["scan_scope"] or {}).get("kind")
    if scope != "full":
        return _all_unproven(R_AGAINST_SCOPE, f"the against-run scan_scope is {scope!r}, not "
                             "'full'; a diff/partial run is not a whole-tree pre-patch baseline")

    if not chosen:                              # honest empty result, not a precondition failure
        return pv

    against["coverage"] = {str(a.get("name")): a.get("coverage_verdict")
                           for a in (manifest.get("arms") or []) if isinstance(a, dict)
                           and a.get("name")}
    scanner_arms = {a.name: a for a in arms if getattr(a, "kind", "") == "scanner"}
    needed = sorted({s for f in chosen for s in f.corroboration.deterministic_sources})

    control_results, pv.control_arms, _, _, _ = _run_needed(
        target, scanner_arms, needed, out_dir, CONTROL_SUBDIR,
        run_id=run_id, collected_at=collected_at)
    patched_results, pv.arms, pv.applied, pv.apply_error, deleted = _run_needed(
        target, scanner_arms, needed, out_dir, VERIFY_SUBDIR, run_id=run_id,
        collected_at=collected_at, patch_path=patch_path,
        deleted_candidates=frozenset(_primary_uri(f) for f in chosen))
    if not pv.applied:
        pv.results = [_unproven(f, f"{R_PATCH_NOT_APPLIED}: patch did not apply cleanly to a "
                                   f"scratch copy: {pv.apply_error}") for f in chosen]
        return pv

    unexplained = {name: _unexplained(res.findings,
                                      control_results[name].findings if name in control_results
                                      else [])
                   for name, res in patched_results.items()}
    pv.new_findings = sum(len(v) for v in unexplained.values())
    pv.results = [_verdict_against(f, control_results, patched_results, unexplained,
                                   against["coverage"], deleted) for f in chosen]
    return pv


# --------------------------------------------------------------------------- #
# evidence: manifest artifacts + decision-store records (machine, non-closing)
# --------------------------------------------------------------------------- #

def producer_label(pv: PatchVerification) -> str:
    """`semgrep 1.2.3, gitleaks 8.18.0` — the scanners that vouched, with versions."""
    parts = [f"{a['name']} {a['tool_version']}" if a.get("tool_version") else a["name"]
             for a in pv.arms]
    return ", ".join(parts) or PRODUCER


def _against_binding(pv: PatchVerification) -> dict:
    """The extra evidence an `--against` verdict binds to (empty in the
    current-tree mode): the old run's identity + manifest sha256, both the
    control and patched scanner versions/rulesets/coverage, and any global
    precondition that fired. This extends trust to a MUTABLE local artifact
    (an unsigned run dir), so what it was is recorded, not assumed."""
    if pv.mode != "against":
        return {}
    return {"mode": "against", "against": pv.against, "precondition": pv.precondition,
            "control_arms": pv.control_arms, "patched_arms": pv.arms}


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
                    "decided_by": "machine", "independent": True, "non_closing": True,
                    **_against_binding(pv)})
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
                    "sources": [asdict(s) for s in r.sources], **_against_binding(pv)}))
    return events
