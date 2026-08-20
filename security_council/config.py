"""`.security-council.yaml` loading (minimal for the Blue MVP)."""

from __future__ import annotations

import copy
from pathlib import Path

import yaml

DEFAULT_CONFIG: dict = {
    "defaults": {"max_concurrency": 4, "min_distinct_vendors": 2},
    "arms": {"enabled": ["semgrep", "gitleaks", "osv-scanner"]},
    "policy": {"fail_on_severity": "high", "min_arms_ok": 1},
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
