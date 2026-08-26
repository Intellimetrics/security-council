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
    # min_arms_ok is a FLOOR on successful arms, not a tolerance for failed ones:
    # any arm that fails, verifies nothing, or covers only part of its scope
    # still degrades the run to exit 3 (a partial scan is never "clean"). With
    # zero successful arms the run is degraded regardless of this value.
    # gate_baseline "new" gates only findings absent from the operator-set
    # baseline (`security-council baseline set`); "all" (default) gates
    # everything. With no baseline set, everything gates either way.
    "policy": {"fail_on_severity": "high", "min_arms_ok": 1,
               "auto_suppress": False, "accept_suppression_risk": False,
               "shadow_runs": 5, "suppress_below": 0.10,
               "suppression_expiry_days": 90, "gate_baseline": "all"},
    # Decision-store signing (R9 signing lane). require_signatures:
    #   auto    (default) per-store: enforce for a store initialised for
    #           signing or with no decisions yet; warn for a pre-existing
    #           unsigned store until the sunset date in signing.py
    #   enforce a human suppression / outcome mark / baseline applies ONLY
    #           when its ssh-keygen signature verifies against allowed_signers
    #   warn    everything applies; unsigned decisions are reported loudly
    #   off     no verification
    # signing_key: path used by `suppress`, `outcome mark`, `baseline set`
    # (flag --signing-key and $SECURITY_COUNCIL_SIGNING_KEY override it).
    "decisions": {"require_signatures": "auto", "signing_key": None},
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
    # R9 Q2: the gate profiles ENFORCE decision signatures — the level comes
    # from config, never from the store, so deleting store.json cannot lower it.
    "ci": {"policy": {"gate_baseline": "new"},
           "decisions": {"require_signatures": "enforce"}},
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
    "gov": {"policy": {"gate_baseline": "new"},
            "decisions": {"require_signatures": "enforce"}},
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


def load_config(start: Path, *, explicit: Path | None = None,
                ignore_repo: bool = False) -> dict:
    """Load the effective config and record WHERE it came from.

    R12 round 21: `.security-council.yaml` is found by walking the scan target
    and its parents — i.e. it is normally the scanned repository's own file.
    That file chooses the arms, the gate severity, the baseline mode and the
    suppression policy, so a branch that commits one can decide how it is
    scanned. Two operator-side controls: `explicit` loads a file the OPERATOR
    names (no directory walk), and `ignore_repo` uses the defaults and ignores
    any file in the target. Every config carries `_source`, which the manifest
    and summary surface, so a run configured by the repository says so.
    """
    if explicit is not None:
        p = Path(explicit)
        if not p.is_file():
            raise ValueError(f"--config {p}: not a file")
        source = {"kind": "explicit", "path": str(p.resolve())}
    elif ignore_repo:
        cfg = copy.deepcopy(DEFAULT_CONFIG)
        cfg["_source"] = {"kind": "defaults", "path": None,
                          "note": "repository config ignored (--ignore-repo-config)"}
        return cfg
    else:
        p = find_config(start)
        if p is None:
            cfg = copy.deepcopy(DEFAULT_CONFIG)
            cfg["_source"] = {"kind": "defaults", "path": None}
            return cfg
        source = {"kind": "repository", "path": str(p)}
    with open(p) as fh:
        data = yaml.safe_load(fh) or {}
    profile = data.pop("profile", None)
    if profile and profile not in PROFILES:
        # fail-closed: a typo'd profile silently scanning with defaults is a
        # misconfiguration hazard, not a fallback
        raise ValueError(f"unknown profile {profile!r} in {p}; known: {sorted(PROFILES)}")
    problems = validate_config(data)
    if problems:
        # fail-closed, same reasoning as an unknown profile: a config the tool
        # silently misreads is a misconfiguration hazard. A typo'd key is
        # ignored today (defaults are safe), but a WRONG VALUE for a right key
        # — `fail_on_severity: hgh`, `gate_baseline: New` — must not be
        # quietly coerced to something the operator did not choose.
        raise ValueError(f"invalid {p}: " + "; ".join(problems))
    base = deep_merge(DEFAULT_CONFIG, PROFILES[profile]) if profile else DEFAULT_CONFIG
    merged = deep_merge(base, data)
    if profile:
        merged["profile"] = profile
    merged["_source"] = source
    return merged


_POLICY_ENUMS = {"fail_on_severity": {"critical", "high", "medium", "low", "info"},
                 "gate_baseline": {"all", "new"}}
_POLICY_BOOLS = ("auto_suppress", "accept_suppression_risk")
_POLICY_INTS = ("min_arms_ok", "shadow_runs", "suppression_expiry_days")


def validate_config(data: dict) -> list[str]:
    """Problems with a raw config file, or [] (R12: `.security-council.yaml`
    had no validation at all). Unknown keys are reported as warnings-by-name
    so a typo is visible; wrong-typed or out-of-range values are errors."""
    out: list[str] = []
    if not isinstance(data, dict):
        return ["top level must be a mapping"]
    known_top = set(DEFAULT_CONFIG) | {"profile"}
    for k in data:
        if k not in known_top:
            out.append(f"unknown top-level key {k!r} (known: {sorted(known_top)})")
    pol = data.get("policy")
    if pol is not None:
        if not isinstance(pol, dict):
            return out + ["policy must be a mapping"]
        for k in pol:
            if k not in DEFAULT_CONFIG["policy"]:
                out.append(f"unknown policy key {k!r}")
        for k, allowed in _POLICY_ENUMS.items():
            if k in pol and pol[k] not in allowed:
                out.append(f"policy.{k} must be one of {sorted(allowed)}, got {pol[k]!r}")
        for k in _POLICY_BOOLS:
            if k in pol and not isinstance(pol[k], bool):
                out.append(f"policy.{k} must be true/false, got {pol[k]!r}")
        for k in _POLICY_INTS:
            if k in pol and (isinstance(pol[k], bool) or not isinstance(pol[k], int)
                             or pol[k] < 0):
                out.append(f"policy.{k} must be a non-negative integer, got {pol[k]!r}")
        if "suppress_below" in pol:
            v = pol["suppress_below"]
            if isinstance(v, bool) or not isinstance(v, (int, float)) or not 0 <= v <= 1:
                out.append(f"policy.suppress_below must be a number in [0, 1], got {v!r}")
    dec = data.get("decisions")
    if dec is not None:
        if not isinstance(dec, dict):
            return out + ["decisions must be a mapping"]
        for k in dec:
            if k not in DEFAULT_CONFIG["decisions"]:
                out.append(f"unknown decisions key {k!r}")
        lvl = dec.get("require_signatures")
        if lvl is not None and lvl not in ("off", "warn", "enforce", "auto"):
            out.append("decisions.require_signatures must be one of "
                       f"['auto', 'enforce', 'off', 'warn'], got {lvl!r}")
        key = dec.get("signing_key")
        if key is not None and not isinstance(key, str):
            out.append(f"decisions.signing_key must be a path string, got {key!r}")
    arms = data.get("arms")
    if arms is not None:
        if not isinstance(arms, dict):
            return out + ["arms must be a mapping"]
        en = arms.get("enabled")
        if en is not None and (not isinstance(en, list) or not all(isinstance(x, str) for x in en)):
            out.append("arms.enabled must be a list of arm names")
    return out
