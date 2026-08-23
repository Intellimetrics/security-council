"""Gated model-tier entitlements (M-V2, Blue scope).

The vendors' built-in security workflows run on whatever model the CLI is given;
gated tiers are a `--model` swap that sharpens the SAME workflows. This module is
the orthogonal layer that (a) knows which tiers exist and their safeguard
posture, (b) lets an operator DECLARE what they hold, (c) probes availability
WITHOUT ever reading API keys, and (d) enforces the safety rules at preflight.

Scope (user-set 2026-08-23): **Blue gated tiers only** — Anthropic *Mythos* and
OpenAI *Daybreak Blue*. The offensive **Daybreak Red** (`gpt-5.6-cyber`) tier is
KNOWN here so it can be positively refused; routing to it stays blocked for
every workflow until the D5 authorization block + sandbox exist.

Probe ladder (plan §Entitlement design), never reads credentials:
  rung 1 — filesystem/CLI catalog, zero network (codex `~/.codex/models_cache.json`;
           claude has no local model catalog → unverifiable at rung 1).
  rung 2 — provider model list via the CLI's own creds (injected `prober`).
  rung 3 — ~10-token capability probe (injected `prober`), result cached.
  rung 4 — behavioral refusal probe for alias tiers → safeguard_posture.
Rungs 2–4 are injectable so they are testable offline and degrade to
"unverifiable" rather than a false "available". None of these tiers are
provisioned on the dev machine, so rung 1 is the only live rung here.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

SafeguardPosture = str   # "relaxed" | "default" | "unknown"


@dataclass(frozen=True)
class Tier:
    name: str                    # declaration key, e.g. "mythos", "daybreak-blue"
    family: str                  # vendor family: "claude" | "codex"
    model_id: str                # the id passed to the CLI's --model
    snapshot: Optional[str]      # underlying model snapshot, if the tier is an alias
    snapshot_gated: bool         # True only if the snapshot is ITSELF gated (Red's
                                 # cyber fine-tune); False when the alias is gated
                                 # but the snapshot is a GA model (Daybreak Blue)
    safeguard_posture: SafeguardPosture   # gated tiers relax safeguards
    is_red: bool                 # offensive/cyber tier — refused in Blue scope


# The gated tiers we know about. GA models (gpt-5.6-sol, claude-fable-5, ...) are
# deliberately absent: they need no entitlement and carry posture "default".
# Daybreak Blue's snapshot (gpt-5.6-sol) is GA — only the ALIAS is gated — so it
# is not snapshot_gated; Daybreak Red's snapshot (gpt-5.6-cyber) is a distinct
# gated fine-tune, so it is.
KNOWN_TIERS: dict[str, Tier] = {
    "mythos": Tier("mythos", "claude", "claude-mythos-5", None, False, "relaxed", False),
    "daybreak-blue": Tier("daybreak-blue", "codex", "daybreak-blue-latest",
                          "gpt-5.6-sol", False, "relaxed", False),
    "daybreak-red": Tier("daybreak-red", "codex", "daybreak-red-latest",
                         "gpt-5.6-cyber", True, "relaxed", True),
}
_BY_MODEL = {t.model_id: t for t in KNOWN_TIERS.values()}
# match a snapshot to its tier ONLY when the snapshot is itself gated — pinning
# a GA snapshot (gpt-5.6-sol) directly must stay GA, not become the gated alias.
_BY_SNAPSHOT = {t.snapshot: t for t in KNOWN_TIERS.values() if t.snapshot and t.snapshot_gated}


def classify_model(model_id: str | None) -> Tier | None:
    """Return the gated Tier a model id names, or None for GA/unknown models.
    Matches the gated alias first, then a snapshot that is itself gated (Red's
    cyber fine-tune). A GA snapshot used directly (e.g. gpt-5.6-sol) is NOT
    gated — only Daybreak Blue's alias is."""
    if not model_id:
        return None
    return _BY_MODEL.get(model_id) or _BY_SNAPSHOT.get(model_id)


def safeguard_posture_for(model_id: str | None) -> SafeguardPosture:
    t = classify_model(model_id)
    return t.safeguard_posture if t else "default"


# --------------------------------------------------------------------------- #
# declaration (config)
# --------------------------------------------------------------------------- #


def declared_tiers(config: dict) -> dict[str, dict]:
    """`entitlements: [{tier: mythos}, {tier: daybreak-blue, model: ...}]` ->
    {tier_name: declaration}. Unknown tier names are kept (probe reports them
    as unrecognized) rather than silently dropped."""
    out: dict[str, dict] = {}
    for e in config.get("entitlements") or []:
        if isinstance(e, dict) and e.get("tier"):
            out[str(e["tier"])] = dict(e)
        elif isinstance(e, str):
            out[e] = {"tier": e}
    return out


# --------------------------------------------------------------------------- #
# probe ladder
# --------------------------------------------------------------------------- #


@dataclass
class EntitlementResult:
    tier: str
    family: str
    model_id: str
    declared: bool
    available: Optional[bool]       # True/False from a probe; None = unverifiable
    rung: int                       # deepest rung that produced a signal
    safeguard_posture: SafeguardPosture
    is_red: bool
    source: str                     # where the signal came from
    error: Optional[str] = None


def _codex_catalog_slugs() -> set[str]:
    try:
        d = json.load(open(os.path.expanduser("~/.codex/models_cache.json")))
        return {m.get("slug") for m in (d.get("models") or []) if isinstance(m, dict)}
    except (OSError, json.JSONDecodeError, TypeError):
        return set()


def catalog_probe(tier: Tier) -> tuple[Optional[bool], str]:
    """Rung 1: zero-network, zero-credential local catalog check.
    -> (available, source). available None = not determinable at rung 1."""
    if tier.family == "codex":
        slugs = _codex_catalog_slugs()
        if not slugs:
            return None, "no codex model cache"
        # the gated alias is not itself a slug; the snapshot is the observable
        if tier.snapshot and tier.snapshot in slugs:
            return None, f"snapshot {tier.snapshot} present (alias entitlement unverifiable)"
        if tier.snapshot and tier.snapshot not in slugs:
            return False, f"snapshot {tier.snapshot} absent from codex model cache"
        return None, "codex cache read, tier not resolvable by snapshot"
    # claude has no local model catalog
    return None, "no local catalog for claude tiers"


def probe_entitlement(tier_name: str, config: dict, *,
                      prober: Callable[[Tier], EntitlementResult] | None = None,
                      cache_dir: Path | None = None) -> EntitlementResult:
    """Run the ladder for one declared/known tier. rung 1 always runs; rungs 2–4
    run only when a `prober` is supplied (kept injectable so this is testable and
    honest offline — the default result is 'unverifiable', never a false yes)."""
    decl = declared_tiers(config)
    tier = KNOWN_TIERS.get(tier_name)
    if tier is None:
        return EntitlementResult(tier=tier_name, family="?", model_id="?",
                                 declared=tier_name in decl, available=False, rung=0,
                                 safeguard_posture="unknown", is_red=False,
                                 source="unrecognized tier", error="not a known tier")
    avail, source = catalog_probe(tier)
    res = EntitlementResult(
        tier=tier.name, family=tier.family, model_id=tier.model_id,
        declared=tier.name in decl, available=avail, rung=1,
        safeguard_posture=tier.safeguard_posture, is_red=tier.is_red, source=source)
    if prober is not None and avail is not True:
        deep = prober(tier)          # rungs 2–4 (CLI creds / capability / refusal)
        if deep is not None:
            res = deep
    if cache_dir is not None:
        _write_cache(cache_dir, res)
    return res


def _write_cache(cache_dir: Path, res: EntitlementResult) -> None:
    try:
        cache_dir.mkdir(parents=True, exist_ok=True)
        path = cache_dir / "entitlements.json"
        data = {}
        if path.is_file():
            data = json.loads(path.read_text())
        # cache only availability facts, never anything credential-derived
        data[res.tier] = {"available": res.available, "rung": res.rung,
                          "source": res.source, "family": res.family,
                          "model_id": res.model_id}
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2, sort_keys=True))
        os.replace(tmp, path)
    except OSError:
        pass


# --------------------------------------------------------------------------- #
# preflight enforcement
# --------------------------------------------------------------------------- #


@dataclass
class Refusal:
    kind: str                    # "red_refused" | "entitlement_undeclared"
    model_id: str
    tier: str
    detail: str


def preflight(requested_models: list[str | None], config: dict) -> list[Refusal]:
    """Enforce the tier rules before any arm runs. A gated model must be (a) not
    Red, and (b) declared in config.entitlements. Returns refusals (empty = ok).

    Red is refused for EVERY workflow in Blue scope (posture policy, not a
    workflow property). An undeclared gated model is refused so a scan can't
    silently route to a tier the operator never claimed to hold."""
    decl = declared_tiers(config)
    refusals: list[Refusal] = []
    seen: set[str] = set()
    for model_id in requested_models:
        tier = classify_model(model_id)
        if tier is None or tier.model_id in seen:
            continue
        seen.add(tier.model_id)
        if tier.is_red:
            refusals.append(Refusal(
                "red_refused", tier.model_id, tier.name,
                f"the {tier.name} ({tier.model_id}) offensive/cyber tier is refused for all "
                "workflows until the authorization block + sandbox exist (decision D5)"))
        elif tier.name not in decl:
            refusals.append(Refusal(
                "entitlement_undeclared", tier.model_id, tier.name,
                f"model {tier.model_id} needs the {tier.name!r} tier declared in "
                "`entitlements:` — the scan will not route to an unclaimed gated tier"))
    return refusals


def tier_model(tier_name: str) -> str | None:
    """The --model id for a named tier (for the `--tier` CLI convenience)."""
    t = KNOWN_TIERS.get(tier_name)
    return t.model_id if t else None
