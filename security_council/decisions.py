"""Decision store: per-root-cause persistence for suppressions, operator
outcomes, the armed-run shadow counter, and the baseline snapshot.

Layout under ``<target>/.security-council/``:

    decisions/by-root-cause/<hex32>.json   one record per root-cause fingerprint
    decisions/policy_state.json            armed-run counter + policy fingerprint
    baseline/latest.json                   operator-set baseline snapshot
    store.json                             store identity (id, created by/at)
    allowed_signers                        signer roster (OpenSSH format)

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

**Signing** (R9 signing lane, see ``signing.py``): every HUMAN write — a
suppression / accepted-risk decision, an outcome mark, a baseline set — is an
event that can carry an ``ssh-keygen -Y`` signature over a fixed field list
bound to this store's id. On replay the store verifies the event against
``allowed_signers`` with the principal = ``decided_by.operator`` and, when it
verifies, applies the SIGNED values (lifecycle, expiry, context hash, ...),
not whatever the record's mutable block says. Under ``require_signatures:
enforce`` an unsigned, invalid, foreign or unverifiable decision is refused —
the finding reappears and gates, the fail-safe direction. Machine writes
(auto-suppressions) are never signed (Q6) and replay only while the operator's
config still arms auto-suppression.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from pathlib import Path

from . import policy, signing
from .model import FindingInvariantError, DecidedBy, Finding, assert_invariants

SCHEMA_VERSION = 1
# R9/G9: high-assurance (crypto / critical) suppressions are re-affirmed on a
# short leash rather than riding the full 90-day expiry.
HIGH_ASSURANCE_EXPIRY_DAYS = 30
_HEX_RE = re.compile(r":([0-9a-f]{32})$")
# config keys whose change resets the shadow counter (suppression-relevant only)
POLICY_FP_KEYS = ("auto_suppress", "accept_suppression_risk", "shadow_runs",
                  "suppress_below", "suppression_expiry_days")

# The fields a signature covers, per event kind. Fixed lists, NOT "everything
# in the event": machine fields added later (reapplied counters, stamps) must
# not invalidate a human signature, and no human field may be editable
# without invalidating it. `store_id` binds the event to one store (R9 Q4:
# a code-location decision is intrinsically about this codebase).
SIGNED_FIELDS = {
    "human": ("kind", "store_id", "root_cause", "context_hash", "finding_id", "operator",
              "at", "expires_at", "lifecycle", "justification", "vex_justification"),
    "outcome_mark": ("kind", "store_id", "root_cause", "finding_id", "operator", "at",
                     "verdict", "note"),
    "baseline_set": ("kind", "store_id", "run_id", "set_at", "operator", "content_sha256"),
}


@dataclass(frozen=True)
class Signer:
    """The operator's SSH key for `ssh-keygen -Y sign` (private key path, or a
    public key whose private half is in ssh-agent)."""
    key_path: str


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


def signed_payload(event: dict) -> bytes:
    """Canonical bytes a signature over ``event`` covers (see SIGNED_FIELDS)."""
    kind = str(event.get("kind") or "")
    fields = SIGNED_FIELDS["human" if kind.startswith("human_") else kind]
    body = {k: event.get(k) for k in fields}
    body["v"] = signing.PAYLOAD_VERSION
    return signing.canonical(body)


class DecisionStore:
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.dir = self.root / "decisions" / "by-root-cause"
        self.state_path = self.root / "decisions" / "policy_state.json"
        self.baseline_path = self.root / "baseline" / "latest.json"
        self.store_path = self.root / "store.json"
        self.allowed_signers_path = self.root / "allowed_signers"

    # ------------------------------------------------------------------ #
    # store identity + signer roster
    # ------------------------------------------------------------------ #
    def store_meta(self) -> dict | None:
        try:
            meta = json.loads(self.store_path.read_text())
        except (OSError, json.JSONDecodeError):
            return None
        return meta if isinstance(meta, dict) and meta.get("store_id") else None

    def store_id(self) -> str | None:
        return (self.store_meta() or {}).get("store_id")

    def init_store(self, *, operator: str | None, now_iso: str) -> dict:
        """Give the store an identity (idempotent). The id is random, not
        derived from the repo: a first-commit sha is wrong on shallow clones
        and identical across forks, and the point of the id is to be THIS
        store's — committed alongside the records it binds."""
        meta = self.store_meta()
        if meta:
            return meta
        meta = {"schema_version": SCHEMA_VERSION, "store_id": secrets.token_hex(16),
                "created_at": now_iso, "created_by": operator,
                "signing": {"scheme": "sshsig", "namespace": signing.NAMESPACE,
                            "roster": self.allowed_signers_path.name}}
        _atomic_write(self.store_path, meta)
        if not self.allowed_signers_path.exists():
            self.allowed_signers_path.write_text(
                "# security-council decision signers (OpenSSH allowed_signers format).\n"
                "# Add with: security-council decisions trust --principal <operator> "
                "--key ~/.ssh/id_ed25519.pub\n"
                "# Put this file and decisions/ behind CODEOWNERS + required review.\n")
        return meta

    def add_trusted_signer(self, *, principal: str, pubkey_text: str, now_iso: str,
                           operator: str | None = None) -> str:
        """Append one roster line (namespace-scoped). Initialises the store if
        needed, so `decisions trust` is a complete first step."""
        self.init_store(operator=operator or principal, now_iso=now_iso)
        line = signing.roster_line(principal, pubkey_text)
        existing = self.allowed_signers_path.read_text() if self.allowed_signers_path.exists() else ""
        if line.strip() in {ln.strip() for ln in existing.splitlines()}:
            return line
        with open(self.allowed_signers_path, "a") as fh:
            if existing and not existing.endswith("\n"):
                fh.write("\n")
            fh.write(line)
        return line

    def trusted_principals(self) -> list[str]:
        return signing.roster_principals(self.allowed_signers_path)

    def has_decisions(self) -> bool:
        """Any record or baseline at all — 'pre-existing store' for policy `auto`."""
        return (self.dir.is_dir() and any(self.dir.glob("*.json"))) or self.baseline_path.is_file()

    def _sign_event(self, event: dict, signer: Signer | None, *, now_iso: str) -> dict:
        """Attach a signature to a human event and PROVE it verifies against the
        roster for its own principal before it is written (write-time principal
        binding: a key that is not trusted for this operator cannot produce a
        decision that would then be refused on every future scan)."""
        if signer is None:
            return event
        operator = event.get("operator")
        if not signing.valid_principal(operator):
            raise signing.SigningError(
                f"operator {operator!r} cannot be a signing principal: use one token "
                "(no spaces or quotes), e.g. an email address")
        meta = self.init_store(operator=operator, now_iso=now_iso)
        event["store_id"] = meta["store_id"]
        sig = signing.sign(signed_payload(event), key_path=signer.key_path)
        status, detail = signing.verify(signed_payload(event), sig,
                                        allowed_signers=self.allowed_signers_path,
                                        principal=operator)
        if status != signing.VERIFIED:
            raise signing.SigningError(
                f"signature for operator {operator!r} does not verify against "
                f"{self.allowed_signers_path} ({detail}); add the key first: "
                f"security-council decisions trust --principal {operator} --key <pubkey.pub>")
        event["signature"] = {"scheme": "sshsig", "namespace": signing.NAMESPACE,
                              "principal": operator, "sig": sig}
        return event

    def verify_event(self, event: dict) -> tuple[str, str]:
        """(status, detail) for one stored event: verified | unsigned | invalid |
        foreign | unverifiable. `foreign` = a good signature made for another
        store (a transplanted record) — refused under enforce like the rest."""
        sig = event.get("signature") if isinstance(event, dict) else None
        if not isinstance(sig, dict) or not sig.get("sig"):
            return signing.UNSIGNED, "no signature on this event"
        principal = sig.get("principal")
        if principal != event.get("operator"):
            return signing.INVALID, "signature principal does not match the event's operator"
        try:
            payload = signed_payload(event)
        except (KeyError, TypeError) as e:
            return signing.INVALID, f"unsignable event: {e}"[:200]
        status, detail = signing.verify(payload, str(sig["sig"]),
                                        allowed_signers=self.allowed_signers_path,
                                        principal=str(principal))
        if status == signing.VERIFIED and event.get("store_id") != self.store_id():
            return signing.FOREIGN, (f"signed for store {str(event.get('store_id'))[:12]}…, "
                                     f"this store is {str(self.store_id())[:12]}…")
        return status, detail

    @staticmethod
    def _human_event_for(rec: dict, sup: dict) -> dict | None:
        """The history event that created the record's current suppression
        block: same operator, same decided_at. Signatures live on events (Q6),
        so this is what gets verified."""
        db = sup.get("decided_by") or {}
        for ev in reversed(rec.get("history") or []):
            if (isinstance(ev, dict) and str(ev.get("kind", "")).startswith("human_")
                    and ev.get("at") == db.get("decided_at")
                    and ev.get("operator") == db.get("operator")):
                return ev
        return None

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
                              vex_justification: str | None = None,
                              signer: Signer | None = None) -> dict:
        """A human suppression/accepted-risk decision, applied on future scans.
        With ``signer`` the event is signed (and proven to verify) before it is
        written; the signed fields are the ones replay will trust."""
        expires = (_now(now_iso) + timedelta(days=expires_days)).isoformat().replace("+00:00", "Z")
        ref = f"decision:root_cause:{root_cause}"
        rec = self.load(root_cause) or {
            "schema_version": SCHEMA_VERSION, "root_cause": root_cause,
            "finding_id": finding_id, "title": title, "context_hash": context_hash,
            "history": [],
        }
        event = {"at": now_iso, "kind": "human_" + lifecycle, "lifecycle": lifecycle,
                 "operator": operator, "finding_id": finding_id, "root_cause": root_cause,
                 "context_hash": context_hash, "justification": justification,
                 "expires_at": expires, "vex_justification": vex_justification,
                 "store_id": self.store_id()}
        self._sign_event(event, signer, now_iso=now_iso)
        rec["context_hash"] = context_hash
        rec["suppression"] = {
            "lifecycle": lifecycle,
            "decided_by": asdict(DecidedBy(kind="human", decided_at=now_iso, operator=operator)),
            "decision_ref": ref, "expires_at": expires,
            "sarif_suppression": {"kind": "external", "status": "accepted",
                                  "justification": f"{justification} ({ref})"},
            "vex_status": "not_affected" if vex_justification else None,
            "vex_justification": vex_justification,
            "shadow": False, "status": "active",
            "signed": "signature" in event}
        rec["history"].append(event)
        _atomic_write(self._path(root_cause), rec)
        return rec

    # ------------------------------------------------------------------ #
    # replay onto a new scan
    # ------------------------------------------------------------------ #
    def apply_prior_decisions(self, findings: list[Finding], *, now_iso: str,
                              signature_policy: str = "off",
                              machine_replay: bool = True) -> list[dict]:
        """Reapply active stored suppressions; expire (G6) and drift (G8) reopen
        instead. Returns one action row per touched finding, for the manifest.

        ``signature_policy`` is the EFFECTIVE level (``signing.resolve_policy``):
        `off` applies records as written; `warn` verifies and reports but still
        applies; `enforce` applies a human decision only when its event
        verifies — and then applies the SIGNED values, so editing the mutable
        block (a later expiry, a matching context hash) changes nothing.
        ``machine_replay=False`` refuses machine (auto) suppressions — the
        orchestrator passes ``is_armed(config)``: a machine decision needs the
        operator's standing double opt-in, or a forged `kind: auto` record
        would apply in a repo that never enabled auto-suppression."""
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
            base = {"finding_id": f.id, "ref": ref, "title": f.title,
                    "severity": f.severity.label}
            is_human = (sup.get("decided_by") or {}).get("kind") == "human"

            # ---- authenticity (R9 signing lane) -------------------------
            # `view` is what replay READS; `sup` is what it WRITES (status,
            # counters). For a verified human event the view is rebuilt from
            # the signed fields; the record's own block is not trusted.
            view = dict(sup)
            expected_ctx = rec.get("context_hash")
            sig_status, sig_detail, principal = signing.UNCHECKED, "", None
            if not is_human:
                sig_status = signing.MACHINE
                if not machine_replay:
                    actions.append({**base, "action": "ignored_machine_unarmed",
                                    "signature": sig_status,
                                    "detail": "auto-suppression is not armed in the current "
                                              "config; a machine decision is not replayed"})
                    continue
            elif signature_policy != "off":
                ev = self._human_event_for(rec, sup)
                if ev is None:
                    sig_status, sig_detail = signing.UNSIGNED, "no matching human event"
                else:
                    sig_status, sig_detail = self.verify_event(ev)
                    principal = (ev.get("signature") or {}).get("principal")
                if sig_status == signing.VERIFIED:
                    just = ev.get("justification") or ""
                    view.update({
                        "lifecycle": ev.get("lifecycle"),
                        "expires_at": ev.get("expires_at"),
                        "decided_by": asdict(DecidedBy(kind="human", decided_at=ev.get("at"),
                                                       operator=ev.get("operator"))),
                        "decision_ref": f"decision:root_cause:{rc}",
                        "sarif_suppression": {"kind": "external", "status": "accepted",
                                              "justification": f"{just} ({ref})"},
                        "vex_status": "not_affected" if ev.get("vex_justification") else None,
                        "vex_justification": ev.get("vex_justification")})
                    expected_ctx = ev.get("context_hash")
                elif signature_policy == "enforce":
                    actions.append({**base, "action": "refused_signature",
                                    "signature": sig_status, "principal": principal,
                                    "operator": (sup.get("decided_by") or {}).get("operator"),
                                    "detail": sig_detail[:200]})
                    continue
            if sig_status in (signing.UNSIGNED, signing.INVALID, signing.FOREIGN,
                              signing.UNVERIFIABLE) and signature_policy == "warn":
                base["signature_warning"] = True

            # R9/G9: a stored suppression is unsigned on-disk operator state. For
            # high-assurance findings (crypto / critical) it is honored — a human
            # is allowed to suppress those (I7) — but only on a SHORT leash: the
            # effective expiry is clamped so the decision must be re-affirmed,
            # and the reapplication is always surfaced individually in the report.
            effective_expiry = view.get("expires_at")
            clamped = False
            # R12 round 18: the two timestamps were parsed BEFORE the
            # malformed-record guard, so `expires_at: not-a-date` raised an
            # uncaught ValueError and crashed the scan. Validate them first;
            # a record with an unreadable date is malformed and is not applied.
            try:
                if effective_expiry:
                    _now(effective_expiry)
                if (view.get("decided_by") or {}).get("decided_at"):
                    _now(view["decided_by"]["decided_at"])
            except (ValueError, TypeError) as e:
                rec["history"].append({"at": now_iso, "kind": "malformed",
                                       "finding_id": f.id, "detail": f"bad timestamp: {e}"[:200]})
                _atomic_write(self._path(rc), rec)
                actions.append({**base, "action": "ignored_malformed", "signature": sig_status,
                                "detail": f"bad timestamp: {e}"[:200]})
                continue
            if effective_expiry and policy.high_assurance(f):
                decided_at = (view.get("decided_by") or {}).get("decided_at")
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
                actions.append({**base, "action": "reopened_expired", "signature": sig_status,
                                "high_assurance": policy.high_assurance(f)})
            elif f.fingerprints.context_hash != expected_ctx:
                f.disposition.lifecycle = "reopened"                       # G8
                f.disposition.reopen_reason = f"context_drift ({ref})"
                sup["status"] = "drifted"
                rec["history"].append({"at": now_iso, "kind": "drift", "finding_id": f.id,
                                       "context_hash": f.fingerprints.context_hash})
                _atomic_write(self._path(rc), rec)
                actions.append({**base, "action": "reopened_drift", "signature": sig_status,
                                "high_assurance": policy.high_assurance(f)})
            else:
                d = f.disposition
                try:
                    decided_by = DecidedBy(**view["decided_by"])
                    # read every required field inside the guard: R12 round 13
                    # noted that `lifecycle` and `decision_ref` were accessed
                    # BELOW it, so a record missing either raised a KeyError
                    # that escaped the malformed-record handler and crashed the
                    # scan — the very thing this handler exists to prevent.
                    _lifecycle, _ref = view["lifecycle"], view["decision_ref"]
                except (TypeError, KeyError, ValueError) as e:
                    # a malformed/hand-edited record must degrade, never crash the
                    # scan — and an unusable decision is simply not applied, which
                    # is the fail-safe direction (the finding stays open)
                    rec["history"].append({"at": now_iso, "kind": "malformed",
                                           "finding_id": f.id, "detail": str(e)[:200]})
                    _atomic_write(self._path(rc), rec)
                    actions.append({**base, "action": "ignored_malformed",
                                    "signature": sig_status, "detail": str(e)[:200]})
                    continue
                # R12 round 15 follow-up: apply the record, then run the
                # invariants INSIDE a guard. I13 (unknown lifecycle) and the
                # widened I6 (nobody may declare a live finding fixed) now reject
                # states a hand-edited record can carry — and an invariant error
                # here used to escape and crash the scan. A record the model
                # rejects is malformed by definition: revert it and degrade.
                snapshot = (d.lifecycle, d.decided_by, d.decision_ref, d.expires_at,
                            d.sarif_suppression, d.vex_status, d.vex_justification)
                d.lifecycle = _lifecycle
                d.decided_by = decided_by
                d.decision_ref = _ref
                d.expires_at = effective_expiry
                d.sarif_suppression = view.get("sarif_suppression")
                d.vex_status = view.get("vex_status")
                d.vex_justification = view.get("vex_justification")
                try:
                    assert_invariants(f)
                except FindingInvariantError as e:
                    (d.lifecycle, d.decided_by, d.decision_ref, d.expires_at,
                     d.sarif_suppression, d.vex_status, d.vex_justification) = snapshot
                    rec["history"].append({"at": now_iso, "kind": "malformed",
                                           "finding_id": f.id, "detail": str(e)[:200]})
                    _atomic_write(self._path(rc), rec)
                    actions.append({**base, "action": "ignored_malformed",
                                    "signature": sig_status, "detail": str(e)[:200]})
                    continue
                # "stale by repetition": a decision nobody has re-touched across
                # many scans is a set-and-forget risk, so the count is surfaced.
                reapplied = int(sup.get("reapplied_count", 0)) + 1
                sup["reapplied_count"] = reapplied
                sup["last_reapplied_at"] = now_iso
                _atomic_write(self._path(rc), rec)
                actions.append({**base, "action": "reapplied_" + _lifecycle,
                                "operator": (view.get("decided_by") or {}).get("operator"),
                                "decided_at": (view.get("decided_by") or {}).get("decided_at"),
                                "expires_at": effective_expiry,
                                "expiry_clamped": clamped, "reapplied_count": reapplied,
                                "high_assurance": policy.high_assurance(f),
                                "signature": sig_status, "principal": principal})
        return actions

    # ------------------------------------------------------------------ #
    # operator outcomes -> the score history term (humans only)
    # ------------------------------------------------------------------ #
    def mark_outcome(self, *, root_cause: str, finding_id: str, verdict: str,
                     operator: str, now_iso: str, note: str = "", title: str = "",
                     context_hash: str = "", signer: Signer | None = None) -> dict:
        if verdict not in ("true_positive", "false_positive"):
            raise ValueError(f"verdict must be true_positive|false_positive, got {verdict!r}")
        rec = self.load(root_cause) or {
            "schema_version": SCHEMA_VERSION, "root_cause": root_cause,
            "finding_id": finding_id, "title": title, "context_hash": context_hash,
            "history": [],
        }
        event = {"at": now_iso, "kind": "outcome_mark", "verdict": verdict,
                 "operator": operator, "finding_id": finding_id, "note": note,
                 "root_cause": root_cause, "store_id": self.store_id()}
        self._sign_event(event, signer, now_iso=now_iso)
        rec["history"].append(event)
        _atomic_write(self._path(root_cause), rec)
        return rec

    def history_counts(self, *, signature_policy: str = "off",
                       audit: list[dict] | None = None) -> dict[str, dict]:
        """root_cause -> {"confirmed_tp": n, "confirmed_fp": n}, from HUMAN
        outcome_mark events only — never from machine decisions (anti-poisoning).

        Under `enforce` only VERIFIED marks count (an unsigned mark could move
        the scorer — importing false-positive marks is the dangerous direction,
        R9). Under `warn` every human mark counts and the non-verified ones are
        appended to ``audit`` so the run can say so loudly."""
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
                if not (ev.get("kind") == "outcome_mark" and ev.get("operator")
                        and ev.get("decided_by") != "machine"):
                    continue
                if signature_policy != "off":
                    status, detail = self.verify_event(ev)
                    if status != signing.VERIFIED:
                        if audit is not None:
                            audit.append({"root_cause": rec.get("root_cause", ""),
                                          "finding_id": ev.get("finding_id"),
                                          "operator": ev.get("operator"),
                                          "verdict": ev.get("verdict"),
                                          "signature": status, "detail": detail[:200],
                                          "applied": signature_policy != "enforce"})
                        if signature_policy == "enforce":
                            continue
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
                     operator: str | None = None, signer: Signer | None = None) -> dict:
        entries = [{"id": f.get("id"), "title": f.get("title"),
                    "root_cause": (f.get("fingerprints") or {}).get("root_cause"),
                    "context_hash": (f.get("fingerprints") or {}).get("context_hash"),
                    "path_cwe_sink": (f.get("fingerprints") or {}).get("path_cwe_sink"),
                    "severity": (f.get("severity") or {}).get("label"),
                    "uri": ((f.get("locations") or [{}])[0]).get("uri")}
                   for f in findings]
        payload = {"schema_version": SCHEMA_VERSION, "run_id": run_id,
                   "set_at": now_iso, "operator": operator, "findings": entries,
                   "content_sha256": baseline_content_sha256(entries),
                   "store_id": self.store_id()}
        if signer is not None:
            # the baseline is one event: sign the digest + who/when/which run.
            # The digest covers the identity fields, so the signature transitively
            # covers every entry without re-hashing the list into the payload.
            event = {"kind": "baseline_set", "run_id": run_id, "set_at": now_iso,
                     "operator": operator, "content_sha256": payload["content_sha256"],
                     "store_id": self.store_id()}
            self._sign_event(event, signer, now_iso=now_iso)
            payload["store_id"] = event["store_id"]
            payload["signature"] = event["signature"]
        _atomic_write(self.baseline_path, payload)
        return payload

    def load_baseline(self, *, signature_policy: str = "off") -> dict | None:
        """Load the baseline and stamp its integrity state (R9).

        The baseline is gate-load-bearing under ``gate_baseline: "new"``, and it
        is unsigned local state — a forged entry set switches the gate off for
        every finding it names. The recorded ``content_sha256`` is a tamper
        *tripwire*, not a signature: an attacker can recompute it, but a
        hand-edited file that doesn't is refused outright, and the recomputed
        digest is pinned into every run manifest so silent drift is visible
        run-over-run. Real authorship proof is the ``signature`` field: with
        ``signature_policy`` other than `off` it is verified here and reported
        as ``signature``; the caller refuses a non-verified baseline under
        `enforce`."""
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
        if signature_policy == "off":
            bl["signature_status"] = signing.UNCHECKED
        else:
            # verify over the RECOMPUTED digest: a signature made for one entry
            # set must not vouch for an edited one even if `integrity` were
            # somehow bypassed — belt and braces with the tripwire above
            event = {"kind": "baseline_set", "run_id": bl.get("run_id"),
                     "set_at": bl.get("set_at"), "operator": bl.get("operator"),
                     "content_sha256": actual, "store_id": bl.get("store_id"),
                     "signature": bl.get("signature")}
            status, detail = self.verify_event(event)
            bl["signature_status"], bl["signature_detail"] = status, detail
        return bl

    # ------------------------------------------------------------------ #
    # whole-store audit (`decisions verify`)
    # ------------------------------------------------------------------ #
    def verify_store(self, *, signature_policy: str = "enforce") -> dict:
        """Every human decision and the baseline, with its signature status
        and whether the given policy would apply it. Read-only."""
        rows: list[dict] = []
        if self.dir.is_dir():
            for p in sorted(self.dir.glob("*.json")):
                try:
                    rec = json.loads(p.read_text())
                except (OSError, json.JSONDecodeError):
                    rows.append({"record": p.name, "kind": "record", "signature": signing.INVALID,
                                 "detail": "unreadable JSON", "applies": False})
                    continue
                sup = rec.get("suppression")
                if sup and sup.get("status") == "active" and not sup.get("shadow"):
                    if (sup.get("decided_by") or {}).get("kind") == "human":
                        ev = self._human_event_for(rec, sup)
                        status, detail = ((signing.UNSIGNED, "no matching human event")
                                          if ev is None else self.verify_event(ev))
                    else:
                        status, detail = signing.MACHINE, "auto-suppression (never signed)"
                    rows.append({"record": p.name, "kind": "suppression",
                                 "lifecycle": sup.get("lifecycle"),
                                 "operator": (sup.get("decided_by") or {}).get("operator"),
                                 "finding_id": rec.get("finding_id"), "title": rec.get("title"),
                                 "signature": status, "detail": detail[:200],
                                 "applies": _applies(status, signature_policy)})
                for ev in rec.get("history") or []:
                    if ev.get("kind") == "outcome_mark" and ev.get("decided_by") != "machine":
                        status, detail = self.verify_event(ev)
                        rows.append({"record": p.name, "kind": "outcome_mark",
                                     "verdict": ev.get("verdict"), "operator": ev.get("operator"),
                                     "finding_id": ev.get("finding_id"), "at": ev.get("at"),
                                     "signature": status, "detail": detail[:200],
                                     "applies": _applies(status, signature_policy)})
        bl = self.load_baseline(signature_policy="enforce")
        if bl is not None:
            status = bl.get("signature_status")
            rows.append({"record": self.baseline_path.name, "kind": "baseline",
                         "operator": bl.get("operator"), "run_id": bl.get("run_id"),
                         "integrity": bl.get("integrity"), "signature": status,
                         "detail": bl.get("signature_detail", "")[:200],
                         "applies": bl.get("integrity") == "intact"
                         and _applies(status, signature_policy)})
        summary = {"rows": len(rows),
                   "verified": sum(1 for r in rows if r["signature"] == signing.VERIFIED),
                   "not_verified": sum(1 for r in rows if r["signature"] not in
                                       (signing.VERIFIED, signing.MACHINE)),
                   "machine": sum(1 for r in rows if r["signature"] == signing.MACHINE),
                   "would_refuse": sum(1 for r in rows if not r["applies"])}
        return {"store_id": self.store_id(), "roster": self.trusted_principals(),
                "verifier": signing.verifier(), "policy": signature_policy,
                "summary": summary, "rows": rows}


def _applies(status: str, signature_policy: str) -> bool:
    if status == signing.MACHINE:
        return True
    if signature_policy == "enforce":
        return status in signing.ACCEPTED
    return True


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
