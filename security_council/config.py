"""`.security-council.yaml` loading (minimal for the Blue MVP)."""

from __future__ import annotations

import copy
from pathlib import Path

import yaml

DEFAULT_CONFIG: dict = {
    "defaults": {"max_concurrency": 4, "min_distinct_vendors": 2},
    # options: per-arm constructor kwargs, e.g.
    #   arms.options.claude-security: {effort: low, max_budget_usd: 10}
    #   arms.options.codex-security:  {mode: standard, max_cost_usd: 5}
    "arms": {"enabled": ["semgrep", "gitleaks", "osv-scanner"], "options": {}},
    # auto_suppress additionally requires accept_suppression_risk: true (the
    # operator's explicit acknowledgement) and runs shadow for the first
    # policy.shadow_runs runs; crypto and critical findings are never
    # auto-suppressed regardless (guardrails G1/G7, structural via I6/I7).
    # gate_baseline "new" gates only findings absent from the operator-set
    # baseline (`security-council baseline set`); "all" (default) gates
    # everything. With no baseline set, everything gates either way.
    "policy": {"fail_on_severity": "high", "min_arms_ok": 1,
               "auto_suppress": False, "accept_suppression_risk": False,
               "shadow_runs": 5, "suppress_below": 0.10,
               "suppression_expiry_days": 90, "gate_baseline": "all"},
    "reports": {"outdir": ".security-council/runs"},
}


def deep_merge(base: dict, over: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in (over or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


def find_config(start: Path) -> Path | None:
    cur = Path(start).resolve()
    for d in [cur, *cur.parents]:
        p = d / ".security-council.yaml"
        if p.is_file():
            return p
    return None


def load_config(start: Path) -> dict:
    p = find_config(start)
    if p is None:
        return copy.deepcopy(DEFAULT_CONFIG)
    with open(p) as fh:
        data = yaml.safe_load(fh) or {}
    return deep_merge(DEFAULT_CONFIG, data)
