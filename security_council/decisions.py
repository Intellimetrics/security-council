"""Decision store: per-root-cause persistence for suppressions, operator
outcomes, the armed-run shadow counter, and the baseline snapshot.

Layout under ``<target>/.security-council/``:

    decisions/by-root-cause/<hex32>.json   one record per root-cause fingerprint
    decisions/policy_state.json            armed-run counter + policy fingerprint
    baseline/latest.json                   operator-set baseline snapshot

Records are G5-scoped (one root cause — never a rule, CWE, or glob), append an
``history[]`` event for every change, and are written atomically (tmp +
``os.replace``). The store makes two guardrails explicit that v1 enforced only
by construction:

- **G6 expiry -> reopen**: a stored suppression past ``expires_at`` is not
  reapplied; the finding comes back ``lifecycle=reopened`` with the reason, and
  the record is stamped ``expired`` (once).
- **G8 context drift -> advisory-only + re-validate**: a stored suppression
  whose ``context_hash`` no longer matches the finding is not reapplied; the
  finding comes back ``reopened`` for re-validation and the record is stamped
  ``drifted``. A drifted decision never reactivates on its own.

**Anti-poisoning rule** (R3): the score's ``history`` term is fed ONLY by human
``outcome mark`` events. Automatic suppressions and shadow decisions are
recorded for audit but never count toward ``history_counts()`` — machine
decisions must not feed the prior that grounds future machine decisions.

**Shadow counter** (G4): ``armed_runs_completed`` counts only runs where
auto-suppression was actually armed, and resets to zero whenever the
suppression-relevant policy config changes (R3: a stored counter flips the
census's fail-safe direction; the reset keeps shadow mode from being burned by
runs under a different policy, and unarmed scans never consume shadow runs).

**Baseline** (D7 adoption lane): ``baseline/latest.json`` is an operator-gated
pointer set via ``security-council baseline set``; ``annotate_baseline`` matches
current findings greedily 1:1 by root_cause -> context_hash -> path_cwe_sink and
stamps SARIF ``baselineState`` (new/unchanged/updated; unmatched baseline
entries are reported ``absent``).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import asdict
from datetime import datetime, timedelta
from pathlib import Path

from . import policy
from .model import DecidedBy, Finding, assert_invariants

SCHEMA_VERSION = 1
# R9/G9: high-assurance (crypto / critical) suppressions are re-affirmed on a
# short leash rather than riding the full 90-day expiry.
HIGH_ASSURANCE_EXPIRY_DAYS = 30
_HEX_RE = re.compile(r":([0-9a-f]{32})$")
# config keys whose change resets the shadow counter (suppression-relevant only)
POLICY_FP_KEYS = ("auto_suppress", "accept_suppression_risk", "shadow_runs",
                  "suppress_below", "suppression_expiry_days")


def _now(now_iso: str) -> datetime:
    return datetime.fromisoformat(now_iso.replace("Z", "+00:00"))


def _slug(root_cause: str) -> str:
    m = _HEX_RE.search(root_cause or "")
    if not m:
        raise ValueError(f"not a root-cause fingerprint: {root_cause!r}")
    return m.group(1)


def _atomic_write(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True))
    os.replace(tmp, path)


def policy_fingerprint(config: dict) -> str:
    from .policy import POLICY_DEFAULTS
    cfg = {**POLICY_DEFAULTS, **(config.get("policy") or {})}
    key = json.dumps({k: cfg.get(k) for k in POLICY_FP_KEYS}, sort_keys=True)
    return hashlib.sha256(key.encode()).hexdigest()


class DecisionStore:
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.dir = self.root / "decisions" / "by-root-cause"
        self.state_path = self.root / "decisions" / "policy_state.json"
        self.baseline_path = self.root / "baseline" / "latest.json"

    # ------------------------------------------------------------------ #
    # records
    # ------------------------------------------------------------------ #
    def _path(self, root_cause: str) -> Path:
        return self.dir / f"{_slug(root_cause)}.json"

    def load(self, root_cause: str) -> dict | None:
        try:
            rec = json.loads(self._path(root_cause).read_text())
            return rec if isinstance(rec, dict) else None
        except (OSError, json.JSONDecodeError, ValueError):
            return None

    def _record_for(self, f: Finding) -> dict:
        return self.load(f.fingerprints.root_cause) or {
            "schema_version": SCHEMA_VERSION,
            "root_cause": f.fingerprints.root_cause,
            "finding_id": f.id, "title": f.title,
            "context_hash": f.fingerprints.context_hash,
            "history": [],
        }

    def record_suppression(self, f: Finding, *, now_iso: str, shadow: bool = False) -> None:
        """Persist the suppression policy.py just applied — or, in shadow mode,
        only the audit event of what WOULD have been suppressed (a shadow
        decision is never stored as an applicable suppression)."""
        rec = self._record_for(f)
        d = f.disposition
        if shadow:
            rec["history"].append({"at": now_iso, "kind": "shadow_suppress", "finding_id": f.id})
        else:
            rec["suppression"] = {
                "lifecycle": d.lifecycle, "decided_by": asdict(d.decided_by),
                "decision_ref": d.decision_ref, "expires_at": d.expires_at,
                "sarif_suppression": d.sarif_suppression,
                "vex_status": d.vex_status, "vex_justification": d.vex_justification,
                "shadow": False, "status": "active"}
            rec["context_hash"] = f.fingerprints.context_hash
            rec["history"].append({"at": now_iso, "kind": "suppress", "finding_id": f.id,
                                   "expires_at": d.expires_at})
        _atomic_write(self._path(f.fingerprints.root_cause), rec)

    def record_human_decision(self, *, root_cause: str, context_hash: str, finding_id: str,
                              title: str, operator: str, justification: str, now_iso: str,
                              lifecycle: str = "suppressed", expires_days: int = 90,
                              vex_justification: str | None = None) -> dict:
        """A human suppression/accepted-risk decision, applied on future scans."""
        expires = (_now(now_iso) + timedelta(days=expires_days)).isoformat().replace("+00:00", "Z")
        ref = f"decision:root_cause:{root_cause}"
        rec = self.load(root_cause) or {
            "schema_version": SCHEMA_VERSION, "root_cause": root_cause,
            "finding_id": finding_id, "title": title, "context_hash": context_hash,
            "history": [],
        }
        rec["context_hash"] = context_hash
        rec["suppression"] = {
            "lifecycle": lifecycle,
            "decided_by": asdict(DecidedBy(kind="human", decided_at=now_iso, operator=operator)),
            "decision_ref": ref, "expires_at": expires,
            "sarif_suppression": {"kind": "external", "status": "accepted",
                                  "justification": f"{justification} ({ref})"},
            "vex_status": "not_affected" if vex_justification else None,
            "vex_justification": vex_justification,
            "shadow": False, "status": "active"}
        rec["history"].append({"at": now_iso, "kind": "human_" + lifecycle,
                               "operator": operator, "finding_id": finding_id,
                               "justification": justification, "expires_at": expires})
        _atomic_write(self._path(root_cause), rec)
        return rec

    # ------------------------------------------------------------------ #
    # replay onto a new scan
    # ------------------------------------------------------------------ #
    def apply_prior_decisions(self, findings: list[Finding], *, now_iso: str) -> list[dict]:
        """Reapply active stored suppressions; expire (G6) and drift (G8) reopen
        instead. Returns one action row per touched finding, for the manifest."""
        actions: list[dict] = []
        for f in findings:
            rc = f.fingerprints.root_cause
            rec = self.load(rc)
            sup = (rec or {}).get("suppression")
            if not rec or not sup or sup.get("shadow"):
                continue
            if sup.get("status") != "active":
                continue
            ref = sup.get("decision_ref")
            # R9/G9: a stored suppression is unsigned on-disk operator state. For
            # high-assurance findings (crypto / critical) it is honored — a human
            # is allowed to suppress those (I7) — but only on a SHORT leash: the
            # effective expiry is clamped so the decision must be re-affirmed,
            # and the reapplication is always surfaced individually in the report.
            effective_expiry = sup.get("expires_at")
            clamped = False
            if effective_expiry and policy.high_assurance(f):
                decided_at = (sup.get("decided_by") or {}).get("decided_at")
                if decided_at:
                    cap = (_now(decided_at)
                           + timedelta(days=HIGH_ASSURANCE_EXPIRY_DAYS)).isoformat()
                    cap = cap.replace("+00:00", "Z")
                    if cap < effective_expiry:
                        effective_expiry, clamped = cap, True
            if not effective_expiry or _now(now_iso) >= _now(effective_expiry):
                f.disposition.lifecycle = "reopened"                       # G6
                reason = "suppression_expired" + ("_high_assurance" if clamped else "")
                f.disposition.reopen_reason = f"{reason} ({ref})"
                sup["status"] = "expired"
                rec["history"].append({"at": now_iso, "kind": "expire", "finding_id": f.id,
                                       "high_assurance_clamp": clamped})
                _atomic_write(self._path(rc), rec)
                actions.append({"finding_id": f.id, "action": "reopened_expired", "ref": ref,
                                "title": f.title, "severity": f.severity.label,
                                "high_assurance": policy.high_assurance(f)})
            elif f.fingerprints.context_hash != rec.get("context_hash"):
                f.disposition.lifecycle = "reopened"                       # G8
                f.disposition.reopen_reason = f"context_drift ({ref})"
                sup["status"] = "drifted"
                rec["history"].append({"at": now_iso, "kind": "drift", "finding_id": f.id,
                                       "context_hash": f.fingerprints.context_hash})
                _atomic_write(self._path(rc), rec)
                actions.append({"finding_id": f.id, "action": "reopened_drift", "ref": ref,
                                "title": f.title, "severity": f.severity.label,
                                "high_assurance": policy.high_assurance(f)})
            else:
                d = f.disposition
                try:
                    decided_by = DecidedBy(**sup["decided_by"])
                    # read every required field inside the guard: R12 round 13
                    # noted that `lifecycle` and `decision_ref` were accessed
                    # BELOW it, so a record missing either raised a KeyError
                    # that escaped the malformed-record handler and crashed the
                    # scan — the very thing this handler exists to prevent.
                    _lifecycle, _ref = sup["lifecycle"], sup["decision_ref"]
                except (TypeError, KeyError, ValueError) as e:
                    # a malformed/hand-edited record must degrade, never crash the
                    # scan — and an unusable decision is simply not applied, which
                    # is the fail-safe direction (the finding stays open)
                    rec["history"].append({"at": now_iso, "kind": "malformed",
                                           "finding_id": f.id, "detail": str(e)[:200]})
                    _atomic_write(self._path(rc), rec)
                    actions.append({"finding_id": f.id, "action": "ignored_malformed",
                                    "ref": ref, "title": f.title,
                                    "severity": f.severity.label, "detail": str(e)[:200]})
                    continue
                d.lifecycle = _lifecycle
                d.decided_by = decided_by
                d.decision_ref = _ref
                d.expires_at = effective_expiry
                d.sarif_suppression = sup.get("sarif_suppression")
                d.vex_status = sup.get("vex_status")
                d.vex_justification = sup.get("vex_justification")
                assert_invariants(f)
                # "stale by repetition": a decision nobody has re-touched across
                # many scans is a set-and-forget risk, so the count is surfaced.
                reapplied = int(sup.get("reapplied_count", 0)) + 1
                sup["reapplied_count"] = reapplied
                sup["last_reapplied_at"] = now_iso
                _atomic_write(self._path(rc), rec)
                actions.append({"finding_id": f.id, "action": "reapplied_" + sup["lifecycle"],
                                "ref": ref, "title": f.title, "severity": f.severity.label,
                                "operator": (sup.get("decided_by") or {}).get("operator"),
                                "decided_at": (sup.get("decided_by") or {}).get("decided_at"),
                                "expires_at": effective_expiry,
                                "expiry_clamped": clamped, "reapplied_count": reapplied,
                                "high_assurance": policy.high_assurance(f)})
        return actions

    # ------------------------------------------------------------------ #
    # operator outcomes -> the score history term (humans only)
    # ------------------------------------------------------------------ #
    def mark_outcome(self, *, root_cause: str, finding_id: str, verdict: str,
                     operator: str, now_iso: str, note: str = "", title: str = "",
                     context_hash: str = "") -> dict:
        if verdict not in ("true_positive", "false_positive"):
            raise ValueError(f"verdict must be true_positive|false_positive, got {verdict!r}")
        rec = self.load(root_cause) or {
            "schema_version": SCHEMA_VERSION, "root_cause": root_cause,
            "finding_id": finding_id, "title": title, "context_hash": context_hash,
            "history": [],
        }
        rec["history"].append({"at": now_iso, "kind": "outcome_mark", "verdict": verdict,
                               "operator": operator, "finding_id": finding_id, "note": note})
        _atomic_write(self._path(root_cause), rec)
        return rec

    def history_counts(self) -> dict[str, dict]:
        """root_cause -> {"confirmed_tp": n, "confirmed_fp": n}, from HUMAN
        outcome_mark events only — never from machine decisions (anti-poisoning)."""
        out: dict[str, dict] = {}
        if not self.dir.is_dir():
            return out
        for p in sorted(self.dir.glob("*.json")):
            try:
                rec = json.loads(p.read_text())
            except (OSError, json.JSONDecodeError):
                continue
            counts = {"confirmed_tp": 0, "confirmed_fp": 0}
            for ev in rec.get("history") or []:
                # L1 anti-poisoning: ONLY human outcome_mark events count — a
                # machine event (verify-fix evidence) is ignored even if it
                # carries kind==outcome_mark and a copied operator field.
                if (ev.get("kind") == "outcome_mark" and ev.get("operator")
                        and ev.get("decided_by") != "machine"):
                    if ev.get("verdict") == "true_positive":
                        counts["confirmed_tp"] += 1
                    elif ev.get("verdict") == "false_positive":
                        counts["confirmed_fp"] += 1
            if counts["confirmed_tp"] or counts["confirmed_fp"]:
                out[rec.get("root_cause", "")] = counts
        return out

    # ------------------------------------------------------------------ #
    # verify-fix evidence — machine, NON-CLOSING (M-V4b, R6 L1/L3)
    # ------------------------------------------------------------------ #
    def record_verify_evidence(self, *, root_cause: str, finding_id: str, verdict: str,
                               patch_sha256: str, base_commit: str | None, producer: str,
                               now_iso: str, model: str | None = None, note: str = "",
                               title: str = "", context_hash: str = "") -> dict:
        """Attach a vendor verify-fix verdict as machine EVIDENCE bound to the
        exact patch. It informs a human but can NEVER close a finding, feed the
        score history term (L1: kind != outcome_mark, decided_by machine), or
        become a panel vote (L3: it lives here, not in validation)."""
        if verdict not in ("fixed", "not_fixed", "unproven"):
            raise ValueError(f"verify verdict must be fixed|not_fixed|unproven, got {verdict!r}")
        rec = self.load(root_cause) or {
            "schema_version": SCHEMA_VERSION, "root_cause": root_cause,
            "finding_id": finding_id, "title": title, "context_hash": context_hash,
            "history": [],
        }
        ev = {"at": now_iso, "kind": "vendor_verify_fix", "decided_by": "machine",
              "verdict": verdict, "patch_sha256": patch_sha256, "base_commit": base_commit,
              "producer": producer, "model": model, "finding_id": finding_id, "note": note}
        rec["history"].append(ev)
        rec.setdefault("verify_evidence", []).append(ev)
        _atomic_write(self._path(root_cause), rec)
        return ev

    def verify_evidence(self, root_cause: str) -> list[dict]:
        return (self.load(root_cause) or {}).get("verify_evidence") or []

    # ------------------------------------------------------------------ #
    # armed-run shadow counter (G4)
    # ------------------------------------------------------------------ #
    def _state(self) -> dict:
        try:
            st = json.loads(self.state_path.read_text())
            return st if isinstance(st, dict) else {}
        except (OSError, json.JSONDecodeError):
            return {}

    def armed_runs_completed(self, config: dict) -> int:
        st = self._state()
        if st.get("policy_fingerprint") != policy_fingerprint(config):
            return 0                     # policy changed -> full shadow again
        return int(st.get("armed_runs", 0))

    def bump_armed_runs(self, config: dict, *, run_id: str, now_iso: str) -> int:
        fp = policy_fingerprint(config)
        n = self.armed_runs_completed(config) + 1
        _atomic_write(self.state_path, {"schema_version": SCHEMA_VERSION,
                                        "policy_fingerprint": fp, "armed_runs": n,
                                        "last_run": run_id, "updated_at": now_iso})
        return n

    # ------------------------------------------------------------------ #
    # baseline (operator-gated pointer)
    # ------------------------------------------------------------------ #
    def set_baseline(self, findings: list[dict], *, run_id: str, now_iso: str,
                     operator: str | None = None) -> dict:
        entries = [{"id": f.get("id"), "title": f.get("title"),
                    "root_cause": (f.get("fingerprints") or {}).get("root_cause"),
                    "context_hash": (f.get("fingerprints") or {}).get("context_hash"),
                    "path_cwe_sink": (f.get("fingerprints") or {}).get("path_cwe_sink"),
                    "severity": (f.get("severity") or {}).get("label"),
                    "uri": ((f.get("locations") or [{}])[0]).get("uri")}
                   for f in findings]
        payload = {"schema_version": SCHEMA_VERSION, "run_id": run_id,
                   "set_at": now_iso, "operator": operator, "findings": entries,
                   "content_sha256": baseline_content_sha256(entries)}
        _atomic_write(self.baseline_path, payload)
        return payload

    def load_baseline(self) -> dict | None:
        """Load the baseline and stamp its integrity state (R9).

        The baseline is gate-load-bearing under ``gate_baseline: "new"``, and it
        is unsigned local state — a forged entry set switches the gate off for
        every finding it names. The recorded ``content_sha256`` is a tamper
        *tripwire*, not a signature: an attacker can recompute it, but a
        hand-edited file that doesn't is refused outright, and the recomputed
        digest is pinned into every run manifest so silent drift is visible
        run-over-run. Real authorship proof needs the signing lane."""
        try:
            bl = json.loads(self.baseline_path.read_text())
        except (OSError, json.JSONDecodeError):
            return None
        if not isinstance(bl, dict):
            return None
        actual = baseline_content_sha256(bl.get("findings") or [])
        recorded = bl.get("content_sha256")
        bl["content_sha256_actual"] = actual
        if recorded is None:
            # A baseline with no digest is REFUSED, not honored: "just omit the
            # field" would otherwise be the cheapest bypass of the whole gate.
            # Pre-R9 baselines are re-created with one `baseline set` run.
            bl["integrity"] = "unpinned"
        elif recorded == actual:
            bl["integrity"] = "intact"
        else:
            bl["integrity"] = "tampered"       # refused by the caller (fail-safe)
        return bl


def baseline_content_sha256(entries: list[dict]) -> str:
    """Digest over the identity-bearing baseline fields, order-independent."""
    keyed = sorted(json.dumps({k: e.get(k) for k in
                               ("id", "root_cause", "context_hash", "path_cwe_sink")},
                              sort_keys=True) for e in entries)
    return hashlib.sha256("\x00".join(keyed).encode()).hexdigest()


def annotate_baseline(findings: list[Finding], baseline: dict, *, partial: bool = False) -> dict:
    """Greedy 1:1 match (root_cause -> context_hash -> path_cwe_sink); stamps
    `baseline_state` on every finding and returns the delta summary.

    `partial=True` (a diff/change-scoped run): an unmatched baseline entry is NOT
    reported `absent` — a finding missing from a partial scan may simply be out
    of the diff's scope, not resolved. Reporting it absent would falsely claim a
    fix. Absent accounting is only meaningful on a full scan."""
    entries = list(baseline.get("findings") or [])
    unmatched = {i: e for i, e in enumerate(entries)}
    resolved: dict[str, str] = {}

    def _take(f: Finding, key: str, equal_unchanged: bool) -> bool:
        want = getattr(f.fingerprints, key)
        for i, e in unmatched.items():
            if e.get(key) and e[key] == want:
                same_ctx = e.get("context_hash") == f.fingerprints.context_hash
                resolved[f.id] = "unchanged" if (equal_unchanged and same_ctx) else "updated"
                del unmatched[i]
                return True
        return False

    for f in findings:
        # only a root-cause match with identical context is "unchanged"; a
        # context/sink-tier match means the identity moved -> "updated"
        (_take(f, "root_cause", True)
         or _take(f, "context_hash", False)
         or _take(f, "path_cwe_sink", False))
    for f in findings:
        f.baseline_state = resolved.get(f.id, "new")
    counts = {"new": 0, "unchanged": 0, "updated": 0}
    for f in findings:
        counts[f.baseline_state] += 1
    # a partial (diff) scan cannot conclude anything about findings it didn't look for
    absent = ([] if partial
              else [{"id": e.get("id"), "title": e.get("title")} for e in unmatched.values()])
    return {"baseline_run": baseline.get("run_id"), **counts, "partial": partial,
            "absent": len(absent), "absent_findings": absent,
            "out_of_scope": len(unmatched) if partial else 0}
