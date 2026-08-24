"""Fitted-calibration records at runtime. The loader is a TRUST BOUNDARY (R7).

A calibration record is *data that injects logits into score.py* — a corrupt or
hostile record could drive whole families toward the suppression threshold or
reorder triage. So loading fails closed to the hand-set prior: schema and scope
are validated, per-family logits are clamped to ±LOGIT_CLAMP, families fitted
on fewer than MIN_DETECTIONS train detections are dropped, and any failure
returns no record plus reasons that land in the manifest.

Application policy (R7 Q1/Q2, council-reviewed):
- ``score.calibration: off`` (default) — never applied.
- ``auto`` — the packaged record applies ONLY when this run's scanner version
  and ruleset match the record's pins; otherwise the run falls back to prior
  with a manifest note (never a silent version-mismatched application).
- an explicit path — operator opt-in; a pin mismatch is applied but loudly
  recorded as a warning in the manifest.

Scope of application (``Calibration.base_for``): deterministic singletons whose
every provenance family is in the record's fitted source set, whose primary
location's language is in the record's fitted language set, and whose CWE
family is in the table. Everything else keeps the prior base. The fitted base
replaces PRIOR + W_DETERMINISTIC only; panel/coverage/history terms and every
clamp are untouched by design.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .model import Finding

RECORD_SCHEMA = "security-council/calibration/v1"
LOGIT_CLAMP = 2.5
MIN_DETECTIONS = 30
PACKAGED_RECORD = Path(__file__).parent / "data" / "calibration-owasp-benchmark-java-1.2.json"


@dataclass(frozen=True)
class Calibration:
    record_id: str
    families: dict[str, float]        # cwe_family -> deploy logit (post-clamp)
    source_families: frozenset[str]   # arm families the fit covered (e.g. {"semgrep"})
    languages: frozenset[str]         # file extensions the corpus covered (e.g. {"java"})
    scanner: dict                     # the record's pins (tool_version, ruleset, arm)
    warnings: tuple[str, ...]

    def base_for(self, f: Finding) -> float | None:
        """The fitted base logit for an in-scope finding, else None (prior)."""
        corr = f.corroboration
        if not corr.deterministic_sources or corr.agent_sources:
            return None
        if not {p.family for p in f.provenance} <= self.source_families:
            return None
        if not f.locations:
            return None
        loc = next((x for x in f.locations if x.role == "primary"), f.locations[0])
        ext = loc.uri.rsplit(".", 1)[-1].lower() if "." in loc.uri else ""
        if ext not in self.languages:
            return None
        return self.families.get(f.taxonomy.cwe_family or "")


def load_record(path: str | Path) -> tuple[Calibration | None, list[str]]:
    """Validate + load one record. -> (calibration, problems). Fail-closed:
    any structural problem returns (None, reasons); recoverable oddities
    (clamped logit, dropped low-n family) load with warnings."""
    p = Path(path)
    try:
        rec = json.loads(p.read_text())
    except (OSError, ValueError) as e:
        return None, [f"unreadable record {p}: {e}"]
    if not isinstance(rec, dict) or rec.get("record") != RECORD_SCHEMA:
        return None, [f"not a {RECORD_SCHEMA} record: {p}"]
    scope = rec.get("scope") or {}
    if scope.get("deterministic_singleton") is not True:
        return None, ["record scope is not deterministic_singleton — unsupported"]
    sources = scope.get("source_families") or []
    langs = scope.get("languages") or []
    if not (isinstance(sources, list) and sources and all(isinstance(s, str) for s in sources)):
        return None, ["record scope.source_families missing/invalid"]
    if not (isinstance(langs, list) and langs and all(isinstance(x, str) for x in langs)):
        return None, ["record scope.languages missing/invalid"]
    fams_in = rec.get("families")
    if not isinstance(fams_in, dict) or not fams_in:
        return None, ["record has no fitted families"]
    warnings: list[str] = []
    families: dict[str, float] = {}
    for fam, row in fams_in.items():
        if not isinstance(row, dict) or not isinstance(row.get("logit"), (int, float)) \
                or isinstance(row.get("logit"), bool) or not isinstance(row.get("detections"), int):
            return None, [f"family {fam}: malformed entry (need numeric logit, int detections)"]
        if row["detections"] < MIN_DETECTIONS:
            warnings.append(f"family {fam} dropped: {row['detections']} detections "
                            f"< {MIN_DETECTIONS}")
            continue
        logit = float(row["logit"])
        if abs(logit) > LOGIT_CLAMP:
            clamped = max(-LOGIT_CLAMP, min(LOGIT_CLAMP, logit))
            warnings.append(f"family {fam} logit {logit} clamped to {clamped}")
            logit = clamped
        families[fam] = logit
    if not families:
        return None, ["no usable families after validation"] + warnings
    corpus = rec.get("corpus") or {}
    rid = f"{corpus.get('corpus', 'unknown')}-{corpus.get('version', '?')}" \
          f"@{str(rec.get('created_at', ''))[:10]}"
    return Calibration(record_id=rid, families=families,
                       source_families=frozenset(sources), languages=frozenset(langs),
                       scanner=dict(rec.get("scanner") or {}),
                       warnings=tuple(warnings)), []


def fitted_scores(policy_rows: list[dict]) -> dict[str, dict]:
    """(d)-lite render map from policy.json rows: STRICT-scope fitted scores only
    (calibration == "fitted", i.e. unvalidated deterministic singletons). Values
    carry the deployed post-clamp p, the clamps that raised it, the pre-clamp
    measured p, and the record id — the renderer shows all of it."""
    import math
    out: dict[str, dict] = {}
    for row in policy_rows:
        s = row.get("score") or {}
        if s.get("calibration") != "fitted":
            continue
        lo = s.get("log_odds")
        measured = (round(1.0 / (1.0 + math.exp(-lo)), 4)
                    if isinstance(lo, (int, float)) and not isinstance(lo, bool)
                    else row.get("p_true"))
        out[row["finding_id"]] = {"p": row.get("p_true"), "measured_p": measured,
                                  "clamps": s.get("clamps") or [],
                                  "record": s.get("calibration_record")}
    return out


def resolve(setting: str | None, *, arm_results: list) -> tuple[Calibration | None, dict]:
    """Turn config ``score.calibration`` into (calibration, manifest block).
    `arm_results` are this run's ArmResult rows — auto mode enforces the
    record's scanner pins against the arm that actually ran (R7 Q2)."""
    if not setting or setting == "off":
        return None, {"status": "off"}
    auto = setting == "auto"
    path = PACKAGED_RECORD if auto else Path(setting)
    cal, problems = load_record(path)
    if cal is None:
        return None, {"status": "invalid", "record_path": str(path), "problems": problems}
    meta: dict = {"status": "active", "record": cal.record_id, "record_path": str(path),
                  "warnings": list(cal.warnings)}
    arm_name = cal.scanner.get("arm", "semgrep")
    arm = next((r for r in arm_results if r.name == arm_name), None)
    pin = cal.scanner.get("tool_version")
    ruleset_pin = cal.scanner.get("ruleset")
    if arm is None or not arm.ok:
        # the fitted arm produced nothing this run: the record cannot apply anyway
        return None, {"status": "arm_not_run", "record": cal.record_id, "arm": arm_name}
    from .arms.scanner import SEMGREP_RULESET
    mismatches = []
    if pin and arm.tool_version and arm.tool_version != pin:
        mismatches.append(f"tool_version {arm.tool_version} != record pin {pin}")
    if ruleset_pin and ruleset_pin != SEMGREP_RULESET:
        mismatches.append(f"ruleset {SEMGREP_RULESET} != record pin {ruleset_pin}")
    if mismatches:
        if auto:
            return None, {"status": "refused_pin_mismatch", "record": cal.record_id,
                          "mismatches": mismatches}
        meta["warnings"] = meta["warnings"] + [f"pin mismatch (explicit record kept): {m}"
                                               for m in mismatches]
    return cal, meta
