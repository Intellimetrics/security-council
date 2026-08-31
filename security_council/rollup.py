"""Pattern/recurrence rollup: where repeated rules concentrate.

The IMS dogfood run had 732 finding instances of which 605 came from five
repeated scanner rules. Fingerprints deliberately keep those locations
separate — a repeated rule is NOT one proven root cause without a
source-to-sink trace — so the model never merges them. This module gives the
reports (and the validation sampler) the concentration view instead: groups
of instances sharing (rule id, cwe family), with every instance still listed
individually elsewhere. Presentation may summarize; it may not collapse.
"""

from __future__ import annotations

from dataclasses import dataclass

from .model import Finding

_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# below this many instances a rule is just findings, not a pattern
DEFAULT_MIN_COUNT = 3


def _groupable_rule_id(f: Finding) -> bool:
    """Agent arms synthesize a rule id from taxonomy when the model supplies
    none (`sc/<family>`, `claude-security/<cwe>`, `codex-security/unknown`).
    Grouping those would present a CWE bucket as a "repeated rule" and let
    the sampler collapse DISTINCT agent findings into one representative
    (R17) — so a synthesized id never groups."""
    rid = f.rule.id
    if not f.rule.source_rule_id:                # normalize fallback sc/<family>
        return False
    if rid.endswith("/unknown") or rid.endswith("/uncategorized"):
        return False
    return not rid.startswith("claude-security/")   # always synthesized from CWE


def pattern_key(f: Finding) -> tuple[str, str]:
    if not _groupable_rule_id(f):
        return (f"finding:{f.id}", f.taxonomy.cwe_family)   # unique: never groups
    return (f.rule.id, f.taxonomy.cwe_family)


def _component(f: Finding) -> str | None:
    if not f.locations:
        return None
    uri = f.locations[0].uri
    return uri.split("/", 1)[0] if "/" in uri else uri


@dataclass
class PatternGroup:
    rule: str
    family: str
    members: list[Finding]          # severity-ordered, every instance

    @property
    def count(self) -> int:
        return len(self.members)

    @property
    def highest_severity(self) -> str:
        return self.members[0].severity.label

    @property
    def components(self) -> list[str]:
        return sorted({c for m in self.members if (c := _component(m))})


def pattern_groups(findings: list[Finding], *,
                   min_count: int = DEFAULT_MIN_COUNT) -> list[PatternGroup]:
    """Recurring-rule groups, largest first. Members keep full Finding objects
    so callers (exporters, the validation sampler) can compute gating/review
    overlays themselves instead of this module guessing their policy."""
    # demoted/closed instances stay visible in the register and appendix, but
    # they must not inflate the concentration view (R17: 4 suppressed + 1 open
    # must not read as "5 instances, highest critical")
    live = [f for f in findings
            if f.disposition.lifecycle in ("open", "reopened")
            and f.disposition.state != "refuted"
            and f.disposition.vex_status not in ("not_affected", "fixed")]
    buckets: dict[tuple[str, str], list[Finding]] = {}
    for f in live:
        buckets.setdefault(pattern_key(f), []).append(f)
    groups = [PatternGroup(rule=k[0], family=k[1],
                           members=sorted(ms, key=lambda f: (
                               _SEV_RANK.get(f.severity.label, 9), f.id)))
              for k, ms in buckets.items() if len(ms) >= min_count]
    groups.sort(key=lambda g: (-g.count, _SEV_RANK.get(g.highest_severity, 9), g.rule))
    return groups


def rollup_json(findings: list[Finding], *, min_count: int = DEFAULT_MIN_COUNT,
                limit: int = 20) -> list[dict]:
    """Manifest-safe slice of the rollup (no Finding objects, capped lists)."""
    return [{
        "rule": g.rule,
        "family": g.family,
        "count": g.count,
        "highest_severity": g.highest_severity,
        "components": g.components[:8],
        "representative_locations": [
            f"{m.locations[0].uri}:{m.locations[0].start_line}"
            for m in g.members[:3] if m.locations],
        "representative_ids": [m.id for m in g.members[:3]],
    } for g in pattern_groups(findings, min_count=min_count)[:limit]]
