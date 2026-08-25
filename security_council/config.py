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
    # score.calibration (R7): "off" (default) | "auto" (packaged fitted record,
    # applied ONLY when the run's scanner version+ruleset match the record's
    # pins) | a path to an explicit record (operator opt-in; mismatches warn).
    "score": {"calibration": "off"},
    # Declared gated model-tier entitlements (M-V2). Each entry names a tier the
    # operator holds, e.g. {tier: mythos} or {tier: daybreak-blue}. A scan will
    # not route to an undeclared gated tier, and never to Daybreak Red (Blue scope).
    "entitlements": [],
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

# Profiles (R8 guided surface): one word picks a sensible preset. Resolution
# order is DEFAULT_CONFIG < profile < config file < CLI flags — a profile never
# overrides anything the operator wrote explicitly. `security-council setup`
# writes these same keys out materialized (with comments), so a config file is
# always self-explanatory; `scan --profile X` applies one ad hoc (and, being an
# explicit flag, wins over the file's own arms/policy).
PROFILES: dict[str, dict] = {
    # $0, fastest: deterministic scanners only, defaults everywhere.
    "quick": {},
    # CI gate posture: same $0 arms; only findings NEW since the operator-set
    # baseline fail the build (no baseline set -> everything gates, fail-safe).
    "ci": {"policy": {"gate_baseline": "new"}},
    # Deep audit: adds the three house LLM-CLI reviewer arms (one per vendor
    # family, so corroboration is cross-vendor) and turns on the validation
    # panel. Real vendor cost, on your CLI subscriptions.
    #
    # R12: this previously shipped the two DEDICATED vendor plugin arms
    # (claude-security, codex-security). They remain available via
    # `--arms claude-security,codex-security` and are more thorough, but they
    # are not what a default profile should carry: codex-security needs its own
    # login and separate per-run budget fuses, while the house arms are
    # live-verified on all three CLIs and need neither.
    "deep": {"arms": {"enabled": ["semgrep", "gitleaks", "osv-scanner",
                                  "claude", "codex", "agy"]},
             "defaults": {"validate": True}},
    # Government / compliance posture: $0 arms + CI-style baseline gating; the
    # paperwork itself comes from `report <run> --bundle gov` afterwards.
    "gov": {"policy": {"gate_baseline": "new"}},
}


def resolve_profile(config: dict, name: str | None) -> dict:
    """Apply a profile UNDER an already-loaded config (config keys win)."""
    if not name:
        return config
    if name not in PROFILES:
        raise KeyError(name)
    return deep_merge(deep_merge(DEFAULT_CONFIG, PROFILES[name]), config)


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
    profile = data.pop("profile", None)
    if profile and profile not in PROFILES:
        # fail-closed: a typo'd profile silently scanning with defaults is a
        # misconfiguration hazard, not a fallback
        raise ValueError(f"unknown profile {profile!r} in {p}; known: {sorted(PROFILES)}")
    base = deep_merge(DEFAULT_CONFIG, PROFILES[profile]) if profile else DEFAULT_CONFIG
    merged = deep_merge(base, data)
    if profile:
        merged["profile"] = profile
    return merged
