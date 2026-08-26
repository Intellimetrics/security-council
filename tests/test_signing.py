"""R9 signing lane: `ssh-keygen -Y` signatures over decision-store EVENTS.

Every attack test here carries an `off` control that shows the same edit
succeeding without signing, so a test cannot pass because the attack never
worked in the first place (the R12 vacuity discipline)."""
import dataclasses
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from security_council import decisions as dec
from security_council import signing
from security_council.cli import main as cli_main
from security_council.config import DEFAULT_CONFIG, load_config, resolve_profile, validate_config
from security_council.orchestrator import run_scan
from tests.test_decisions import LATER, NOW
from tests.test_orchestrator import FakeArm, _finding as orch_finding
from tests.test_validate import _finding

pytestmark = pytest.mark.skipif(signing.verifier() is None,
                                reason="ssh-keygen -Y (OpenSSH >= 8.2) not available")

ALICE, BOB, MALLORY = "alice@example", "bob@example", "mallory@example"
SHA = "a" * 64


@pytest.fixture(scope="module")
def keys(tmp_path_factory):
    """Two throwaway ed25519 keypairs: {name: (private_path, public_path)}."""
    d = tmp_path_factory.mktemp("keys")
    out = {}
    for who in (ALICE, BOB):
        priv = d / who.split("@")[0]
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", who, "-f", str(priv)],
                       check=True, capture_output=True)
        out[who] = (priv, priv.with_suffix(".pub"))
    return out


def _store(tmp_path, keys, *trusted):
    """A store initialised for signing with the given principals trusted."""
    store = dec.DecisionStore(tmp_path / ".security-council")
    store.init_store(operator=ALICE, now_iso=NOW)
    for who in trusted:
        store.add_trusted_signer(principal=who, pubkey_text=keys[who][1].read_text(),
                                 now_iso=NOW)
    return store


def _signed_suppress(store, keys, f, *, who=ALICE, days=90, now=NOW):
    return store.record_human_decision(
        root_cause=f.fingerprints.root_cause, context_hash=f.fingerprints.context_hash,
        finding_id=f.id, title=f.title, operator=who, justification="reviewed",
        now_iso=now, expires_days=days, signer=dec.Signer(key_path=str(keys[who][0])))


def _replay(store, f, level, **kw):
    return store.apply_prior_decisions([f], now_iso=LATER, signature_policy=level, **kw)


def _cfg(level="enforce", **policy):
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))
    cfg["policy"].update(policy)
    cfg["decisions"]["require_signatures"] = level
    return cfg


# --------------------------------------------------------------------- #
# signing.py primitives
# --------------------------------------------------------------------- #

def test_canonical_payload_is_field_scoped_and_stable():
    ev = {"kind": "human_suppressed", "store_id": "s", "root_cause": "rc", "context_hash": "c",
          "finding_id": "f", "operator": ALICE, "at": NOW, "expires_at": LATER,
          "lifecycle": "suppressed", "justification": "j", "vex_justification": None}
    base = dec.signed_payload(ev)
    assert base == dec.signed_payload({**ev, "reapplied_count": 9, "signature": {"x": 1}}), \
        "machine fields must not be part of the signed bytes"
    assert base != dec.signed_payload({**ev, "expires_at": "2099-01-01T00:00:00Z"})
    assert base != dec.signed_payload({**ev, "context_hash": "other"})
    assert base != dec.signed_payload({**ev, "store_id": "other-store"})
    assert b" " not in base and b"\n" not in base and b'"v":1' in base


def test_sign_verify_roundtrip_tamper_and_principal_binding(tmp_path, keys):
    roster = tmp_path / "allowed_signers"
    roster.write_text(signing.roster_line(ALICE, keys[ALICE][1].read_text()))
    payload = signing.canonical({"a": 1})
    sig = signing.sign(payload, key_path=keys[ALICE][0])
    assert sig.startswith("-----BEGIN SSH SIGNATURE-----")
    assert signing.verify(payload, sig, allowed_signers=roster, principal=ALICE)[0] == "verified"
    # tampered payload
    assert signing.verify(signing.canonical({"a": 2}), sig, allowed_signers=roster,
                          principal=ALICE)[0] == "invalid"
    # right key, wrong principal (not in roster under that name)
    assert signing.verify(payload, sig, allowed_signers=roster, principal=BOB)[0] == "invalid"
    # a key the roster does not list at all
    sig_bob = signing.sign(payload, key_path=keys[BOB][0])
    assert signing.verify(payload, sig_bob, allowed_signers=roster, principal=ALICE)[0] == "invalid"
    # no roster file
    assert signing.verify(payload, sig, allowed_signers=tmp_path / "nope",
                          principal=ALICE)[0] == "invalid"
    # garbage signature block never raises
    assert signing.verify(payload, "nonsense", allowed_signers=roster, principal=ALICE)[0] == "invalid"


def test_missing_verifier_is_unverifiable_and_signing_refuses(tmp_path, keys, monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda name: None)
    monkeypatch.setattr(signing, "_verifier_cache", {})
    assert signing.verifier() is None
    assert signing.verify(b"x", "-----BEGIN SSH SIGNATURE-----\nx\n", allowed_signers=tmp_path,
                          principal=ALICE)[0] == "unverifiable"
    with pytest.raises(signing.SigningError, match="ssh-keygen"):
        signing.sign(b"x", key_path=keys[ALICE][0])


def test_roster_line_validation(keys):
    line = signing.roster_line(ALICE, keys[ALICE][1].read_text())
    assert line.startswith(f'{ALICE} namespaces="{signing.NAMESPACE}" ssh-ed25519 ')
    with pytest.raises(signing.SigningError, match="single token"):
        signing.roster_line("alice smith", keys[ALICE][1].read_text())
    with pytest.raises(signing.SigningError, match="PRIVATE"):
        signing.roster_line(ALICE, keys[ALICE][0].read_text())
    with pytest.raises(signing.SigningError, match="public key line"):
        signing.roster_line(ALICE, "not a key")
    assert not signing.valid_principal("has space") and not signing.valid_principal("")


# --------------------------------------------------------------------- #
# store: identity, roster, write-time binding
# --------------------------------------------------------------------- #

def test_init_and_trust_are_idempotent(tmp_path, keys):
    store = _store(tmp_path, keys, ALICE)
    sid = store.store_id()
    assert sid and len(sid) == 32
    assert store.init_store(operator=BOB, now_iso=LATER)["store_id"] == sid
    store.add_trusted_signer(principal=ALICE, pubkey_text=keys[ALICE][1].read_text(),
                             now_iso=LATER)
    assert store.trusted_principals() == [ALICE]
    assert store.allowed_signers_path.read_text().count(ALICE) == 1


def test_untrusted_key_or_mismatched_principal_refused_at_write_time(tmp_path, keys):
    store = _store(tmp_path, keys, ALICE)
    f = _finding()
    # BOB is not in the roster at all
    with pytest.raises(signing.SigningError, match="does not verify"):
        _signed_suppress(store, keys, f, who=BOB)
    assert store.load(f.fingerprints.root_cause) is None      # nothing written
    # ALICE's key signing as a trusted principal it does not belong to
    store.add_trusted_signer(principal=BOB, pubkey_text=keys[BOB][1].read_text(), now_iso=NOW)
    with pytest.raises(signing.SigningError, match="does not verify"):
        store.record_human_decision(
            root_cause=f.fingerprints.root_cause, context_hash=f.fingerprints.context_hash,
            finding_id=f.id, title=f.title, operator=BOB, justification="j", now_iso=NOW,
            signer=dec.Signer(key_path=str(keys[ALICE][0])))
    # an operator that cannot be a roster token cannot sign
    with pytest.raises(signing.SigningError, match="principal"):
        store.record_human_decision(
            root_cause=f.fingerprints.root_cause, context_hash=f.fingerprints.context_hash,
            finding_id=f.id, title=f.title, operator="Alice Smith", justification="j",
            now_iso=NOW, signer=dec.Signer(key_path=str(keys[ALICE][0])))


# --------------------------------------------------------------------- #
# replay: enforce / warn / off
# --------------------------------------------------------------------- #

def test_signed_decision_verifies_and_applies_under_enforce(tmp_path, keys):
    store = _store(tmp_path, keys, ALICE)
    rec = _signed_suppress(store, keys, _finding())
    ev = rec["history"][-1]
    assert ev["signature"]["principal"] == ALICE and ev["store_id"] == store.store_id()
    assert rec["suppression"]["signed"] is True
    assert store.verify_event(ev) == ("verified", store.verify_event(ev)[1])
    f = _finding()
    [a] = _replay(store, f, "enforce")
    assert a["action"] == "reapplied_suppressed" and a["signature"] == "verified"
    assert a["principal"] == ALICE and f.disposition.lifecycle == "suppressed"


def test_unsigned_decision_refused_under_enforce_applied_under_warn(tmp_path, keys):
    store = _store(tmp_path, keys, ALICE)
    f0 = _finding()
    store.record_human_decision(                                   # no signer
        root_cause=f0.fingerprints.root_cause, context_hash=f0.fingerprints.context_hash,
        finding_id=f0.id, title=f0.title, operator=ALICE, justification="j", now_iso=NOW)
    f = _finding()
    [a] = _replay(store, f, "enforce")
    assert a["action"] == "refused_signature" and a["signature"] == "unsigned"
    assert f.disposition.lifecycle == "open"                       # stays open, gates
    f = _finding()
    [a] = _replay(store, f, "warn")
    assert a["action"] == "reapplied_suppressed" and a["signature"] == "unsigned"
    assert a["signature_warning"] is True and f.disposition.lifecycle == "suppressed"
    f = _finding()
    [a] = _replay(store, f, "off")
    assert a["action"] == "reapplied_suppressed" and a["signature"] == "unchecked"
    assert "signature_warning" not in a


def test_edited_expiry_in_mutable_block_is_ignored_when_signed(tmp_path, keys):
    """Attack: extend `suppression.expires_at` by hand. The signed event's expiry
    wins under enforce; the `off` control shows the edit working otherwise."""
    for level, expect in (("off", "reapplied_suppressed"), ("enforce", "reopened_expired")):
        target = tmp_path / level
        store = _store(target, keys, ALICE)
        f0 = _finding()
        _signed_suppress(store, keys, f0, days=1)                   # expires before LATER
        path = store._path(f0.fingerprints.root_cause)
        rec = json.loads(path.read_text())
        rec["suppression"]["expires_at"] = "2099-01-01T00:00:00Z"
        path.write_text(json.dumps(rec))
        f = _finding()
        [a] = _replay(store, f, level)
        assert a["action"] == expect, level
        assert a["signature"] == ("verified" if level == "enforce" else "unchecked")


def test_edited_context_hash_cannot_hide_drift_when_signed(tmp_path, keys):
    """Attack: the code under the suppression changed (G8 would reopen), so the
    attacker rewrites the record's context_hash to the new one."""
    for level, expect in (("off", "reapplied_suppressed"), ("enforce", "reopened_drift")):
        target = tmp_path / level
        store = _store(target, keys, ALICE)
        _signed_suppress(store, keys, _finding())
        drifted = _finding()
        drifted.fingerprints = dataclasses.replace(
            drifted.fingerprints, context_hash="contextHash/v1:" + "d" * 32)
        path = store._path(drifted.fingerprints.root_cause)
        rec = json.loads(path.read_text())
        rec["context_hash"] = drifted.fingerprints.context_hash
        path.write_text(json.dumps(rec))
        [a] = _replay(store, drifted, level)
        assert a["action"] == expect, level


def test_edited_signed_field_invalidates_the_event(tmp_path, keys):
    """Attack: edit a field INSIDE the signed event (the justification, the
    lifecycle, the operator). Any of them breaks the signature."""
    store = _store(tmp_path, keys, ALICE)
    _signed_suppress(store, keys, _finding())
    path = store._path(_finding().fingerprints.root_cause)
    pristine = path.read_text()
    for field, value in (("justification", "totally legit"), ("lifecycle", "accepted_risk"),
                         ("expires_at", "2099-01-01T00:00:00Z"), ("operator", BOB)):
        rec = json.loads(pristine)
        rec["history"][-1][field] = value
        if field == "operator":
            rec["suppression"]["decided_by"]["operator"] = BOB
        path.write_text(json.dumps(rec))
        f = _finding()
        [a] = _replay(store, f, "enforce")
        assert a["action"] == "refused_signature", field
        assert a["signature"] == "invalid", field
        assert f.disposition.lifecycle == "open", field
    path.write_text(pristine)
    assert _replay(store, _finding(), "enforce")[0]["action"] == "reapplied_suppressed"


def test_transplanted_record_is_foreign(tmp_path, keys):
    """Attack: copy a legitimately signed record (and the roster) from repo A
    into repo B. The signature is good — for a different store id."""
    a = _store(tmp_path / "A", keys, ALICE)
    _signed_suppress(a, keys, _finding())
    b = _store(tmp_path / "B", keys, ALICE)
    assert a.store_id() != b.store_id()
    src = a._path(_finding().fingerprints.root_cause)
    b.dir.mkdir(parents=True, exist_ok=True)
    shutil.copy(src, b._path(_finding().fingerprints.root_cause))
    ev = json.loads(src.read_text())["history"][-1]
    assert b.verify_event(ev)[0] == "foreign"
    f = _finding()
    [act] = _replay(b, f, "enforce")
    assert act["action"] == "refused_signature" and act["signature"] == "foreign"
    assert f.disposition.lifecycle == "open"
    # control: the same copied record applies in its own store, and under `off` in B
    assert _replay(a, _finding(), "enforce")[0]["action"] == "reapplied_suppressed"
    assert _replay(b, _finding(), "off")[0]["action"] == "reapplied_suppressed"


def test_removing_a_signer_from_the_roster_revokes_their_decisions(tmp_path, keys):
    store = _store(tmp_path, keys, ALICE)
    _signed_suppress(store, keys, _finding())
    store.allowed_signers_path.write_text("# nobody\n")
    f = _finding()
    [a] = _replay(store, f, "enforce")
    assert a["action"] == "refused_signature" and a["signature"] == "invalid"


def test_machine_suppression_replays_only_when_armed(tmp_path):
    """Attack: forge a `kind: auto` record (machine writes are never signed).
    Bounded by: replay only while the operator config arms auto-suppression."""
    store = dec.DecisionStore(tmp_path / ".security-council")
    f0 = _finding()
    rec = {"schema_version": 1, "root_cause": f0.fingerprints.root_cause,
           "finding_id": f0.id, "title": f0.title,
           "context_hash": f0.fingerprints.context_hash, "history": [],
           "suppression": {"lifecycle": "suppressed", "status": "active", "shadow": False,
                           "decided_by": {"kind": "auto", "decided_at": NOW, "model_id": "m",
                                          "prompt_sha256": SHA, "panel_sha256": SHA},
                           "decision_ref": f"decision:root_cause:{f0.fingerprints.root_cause}",
                           "expires_at": "2099-01-01T00:00:00Z",
                           "sarif_suppression": {"kind": "external", "status": "accepted",
                                                 "justification": "forged"},
                           "vex_status": None, "vex_justification": None}}
    store.dir.mkdir(parents=True)
    store._path(f0.fingerprints.root_cause).write_text(json.dumps(rec))
    f = _finding()
    [a] = _replay(store, f, "enforce", machine_replay=False)
    assert a["action"] == "ignored_machine_unarmed" and a["signature"] == "machine"
    assert f.disposition.lifecycle == "open"
    f = _finding()                                                  # control: armed
    [a] = _replay(store, f, "enforce", machine_replay=True)
    assert a["action"] == "reapplied_suppressed" and a["signature"] == "machine"


# --------------------------------------------------------------------- #
# outcome marks and the baseline
# --------------------------------------------------------------------- #

def test_outcome_marks_count_only_when_verified_under_enforce(tmp_path, keys):
    store = _store(tmp_path, keys, ALICE)
    f = _finding()
    rc = f.fingerprints.root_cause
    store.mark_outcome(root_cause=rc, finding_id=f.id, verdict="false_positive", operator=ALICE,
                       now_iso=NOW, signer=dec.Signer(key_path=str(keys[ALICE][0])))
    store.mark_outcome(root_cause=rc, finding_id=f.id, verdict="false_positive", operator=ALICE,
                       now_iso=LATER)                              # unsigned
    assert store.history_counts(signature_policy="enforce") == {rc: {"confirmed_tp": 0,
                                                                     "confirmed_fp": 1}}
    audit: list = []
    assert store.history_counts(signature_policy="warn", audit=audit)[rc]["confirmed_fp"] == 2
    assert len(audit) == 1 and audit[0]["signature"] == "unsigned" and audit[0]["applied"]
    assert store.history_counts()[rc]["confirmed_fp"] == 2          # off


def _bl_row(f):
    return {"id": f.id, "title": f.title,
            "fingerprints": {"root_cause": f.fingerprints.root_cause,
                             "context_hash": f.fingerprints.context_hash,
                             "path_cwe_sink": f.fingerprints.path_cwe_sink},
            "severity": {"label": f.severity.label}, "locations": [{"uri": "app/x.py"}]}


def test_baseline_signature_states(tmp_path, keys):
    store = _store(tmp_path, keys, ALICE)
    f = _finding()
    store.set_baseline([_bl_row(f)], run_id="r1", now_iso=NOW, operator=ALICE,
                       signer=dec.Signer(key_path=str(keys[ALICE][0])))
    bl = store.load_baseline(signature_policy="enforce")
    assert bl["integrity"] == "intact" and bl["signature_status"] == "verified"
    assert store.load_baseline()["signature_status"] == "unchecked"
    # append an entry: digest tripwire AND signature both fail
    doc = json.loads(store.baseline_path.read_text())
    doc["findings"].append({"id": "x", "root_cause": "rootCause/v1:" + "e" * 32})
    store.baseline_path.write_text(json.dumps(doc))
    bl = store.load_baseline(signature_policy="enforce")
    assert bl["integrity"] == "tampered" and bl["signature_status"] == "invalid"
    # recompute the digest (what R9 said an attacker can do): still not signed for it
    doc["content_sha256"] = dec.baseline_content_sha256(doc["findings"])
    store.baseline_path.write_text(json.dumps(doc))
    bl = store.load_baseline(signature_policy="enforce")
    assert bl["integrity"] == "intact" and bl["signature_status"] == "invalid"
    # an unsigned baseline
    store.set_baseline([_bl_row(f)], run_id="r2", now_iso=NOW, operator=ALICE)
    assert store.load_baseline(signature_policy="enforce")["signature_status"] == "unsigned"


def test_orchestrator_refuses_unsigned_baseline_under_enforce(tmp_path, keys):
    """End-to-end: gate_baseline new + enforce. An intact-but-unsigned baseline
    (the R9 'recompute the digest' residual) no longer switches the gate off."""
    target = tmp_path / "repo"
    (target / "app").mkdir(parents=True)
    (target / "app" / "x.py").write_text("q = 1\n")
    finding = orch_finding(source_id="semgrep", kind="scanner", vendor="semgrep")
    store = _store(target, keys, ALICE)

    def _scan(level):
        return run_scan(target, [FakeArm("semgrep", "scanner", "semgrep", [finding])],
                        _cfg(level, gate_baseline="new"), isolate=False)

    store.set_baseline([_bl_row(finding)], run_id="r", now_iso=NOW, operator=ALICE)  # unsigned
    assert _scan("off").exit_code == 0                              # control: intact digest
    run = _scan("enforce")
    assert run.exit_code == 1
    assert any(d["kind"] == "baseline_refused" and "signature unsigned" in d["detail"]
               for d in run.degradations)
    run = _scan("warn")
    assert run.exit_code == 0
    assert any(d["kind"] == "baseline_unsigned" for d in run.degradations)
    store.set_baseline([_bl_row(finding)], run_id="r", now_iso=NOW, operator=ALICE,
                       signer=dec.Signer(key_path=str(keys[ALICE][0])))
    run = _scan("enforce")
    assert run.exit_code == 0
    assert run.manifest["baseline_delta"]["signature"] == "verified"
    assert run.manifest["signature_policy"]["effective"] == "enforce"


# --------------------------------------------------------------------- #
# policy resolution + config
# --------------------------------------------------------------------- #

def test_resolve_policy_auto_is_per_store_with_sunset(tmp_path, keys):
    before, after = "2026-09-01T00:00:00Z", "2027-02-01T00:00:00Z"
    cfg = _cfg("auto")
    r = signing.resolve_policy(cfg, store_initialised=False, store_has_decisions=False,
                               now_iso=before)
    assert r["effective"] == "enforce" and "new store" in r["reason"]
    r = signing.resolve_policy(cfg, store_initialised=False, store_has_decisions=True,
                               now_iso=before)
    assert r["effective"] == "warn" and signing.WARN_SUNSET[:10] in r["reason"]
    r = signing.resolve_policy(cfg, store_initialised=False, store_has_decisions=True,
                               now_iso=after)
    assert r["effective"] == "enforce" and "ended" in r["reason"]
    r = signing.resolve_policy(cfg, store_initialised=True, store_has_decisions=True,
                               now_iso=before)
    assert r["effective"] == "enforce" and "store.json" in r["reason"]
    for lvl in ("off", "warn", "enforce"):
        assert signing.resolve_policy(_cfg(lvl), store_initialised=False,
                                      store_has_decisions=True, now_iso=before)["effective"] == lvl
    with pytest.raises(ValueError, match="require_signatures"):
        signing.resolve_policy(_cfg("yes"), store_initialised=False,
                               store_has_decisions=False, now_iso=before)


def test_ci_and_gov_profiles_enforce_and_config_validates():
    for prof in ("ci", "gov"):
        assert resolve_profile({}, prof)["decisions"]["require_signatures"] == "enforce"
    assert resolve_profile({}, "quick")["decisions"]["require_signatures"] == "enforce"
    assert validate_config({"decisions": {"require_signatures": "enforce"}}) == []
    assert any("require_signatures" in p for p in
               validate_config({"decisions": {"require_signatures": "Enforce"}}))
    assert any("unknown decisions key" in p for p in validate_config({"decisions": {"sign": 1}}))
    assert any("signing_key" in p for p in validate_config({"decisions": {"signing_key": 3}}))


def test_yaml_bare_off_is_accepted(tmp_path):
    """YAML 1.1 reads a bare `off` as boolean False (R13 own pass)."""
    (tmp_path / ".security-council.yaml").write_text("decisions:\n  require_signatures: off\n")
    assert load_config(tmp_path)["decisions"]["require_signatures"] == "off"
    (tmp_path / ".security-council.yaml").write_text("decisions:\n  require_signatures: on\n")
    with pytest.raises(ValueError, match="require_signatures"):
        load_config(tmp_path)


# --------------------------------------------------------------------- #
# CLI + report, end to end
# --------------------------------------------------------------------- #

def _repo(tmp_path, level):
    target = tmp_path / "repo"
    (target / "app").mkdir(parents=True)
    (target / "app" / "x.py").write_text("q = 1\n")
    (target / ".security-council.yaml").write_text(
        f"decisions:\n  require_signatures: {level}\n")
    return target


def _scan(target, finding):
    return run_scan(target, [FakeArm("semgrep", "scanner", "semgrep", [finding])],
                    load_config(target), isolate=False)


def test_cli_signed_flow_end_to_end(tmp_path, keys, capsys):
    target = _repo(tmp_path, "enforce")
    finding = orch_finding(source_id="semgrep", kind="scanner", vendor="semgrep", rc="cli")
    run1 = _scan(target, finding)
    assert run1.exit_code == 1
    [row] = json.loads((run1.out_dir / "findings.json").read_text())
    t = ["--target", str(target)]

    # unsigned write is refused up front with the two steps to fix it
    assert cli_main(["suppress", row["id"], "--operator", ALICE, "--justification", "j",
                     "--run", str(run1.out_dir), *t]) == 2
    err = capsys.readouterr().err
    assert "must be signed" in err and "decisions trust" in err
    assert not (target / ".security-council" / "decisions").exists()

    assert cli_main(["decisions", "init", *t, "--operator", ALICE]) == 0
    assert cli_main(["decisions", "trust", "--principal", ALICE, "--key",
                     str(keys[ALICE][1]), *t]) == 0
    assert "trusted: alice@example namespaces=" in capsys.readouterr().out
    assert cli_main(["suppress", row["id"], "--operator", ALICE, "--justification", "j",
                     "--run", str(run1.out_dir), "--signing-key", str(keys[ALICE][0]), *t]) == 0
    assert "signed by alice@example" in capsys.readouterr().out
    assert cli_main(["decisions", "verify", *t]) == 0
    out = capsys.readouterr().out
    assert "1 verified" in out and "0 would be refused" in out

    run2 = _scan(target, finding)
    assert run2.exit_code == 0
    [pd] = run2.manifest["prior_decisions"]
    assert pd["action"] == "reapplied_suppressed" and pd["signature"] == "verified"
    assert pd["principal"] == ALICE
    sp = run2.manifest["signature_policy"]
    assert sp["effective"] == "enforce" and sp["store_id"] and sp["trusted_principals"] == [ALICE]
    md = (run2.out_dir / "summary.md").read_text()
    assert "✓ verified" in md and "Decision signatures:** enforce" in md
    assert "unsigned local state" not in md

    # tamper with the signed event: refused, gate back on, report says so
    store = dec.DecisionStore(target / ".security-council")
    path = store._path(row["fingerprints"]["root_cause"])
    rec = json.loads(path.read_text())
    rec["history"][-1]["justification"] = "edited"
    path.write_text(json.dumps(rec))
    run3 = _scan(target, finding)
    assert run3.exit_code == 1
    assert any(d["kind"] == "decisions_refused_unsigned" for d in run3.degradations)
    md = (run3.out_dir / "summary.md").read_text()
    assert "REFUSED" in md and "Stored decisions refused" in md
    assert cli_main(["decisions", "verify", *t]) == 1
    assert "REFUSED" in capsys.readouterr().out
    # --json is machine readable
    assert cli_main(["decisions", "verify", "--json", *t]) == 1
    audit = json.loads(capsys.readouterr().out)
    assert audit["summary"]["would_refuse"] == 1 and audit["rows"][0]["signature"] == "invalid"


def test_warn_is_loud(tmp_path, capsys):
    target = _repo(tmp_path, "warn")
    finding = orch_finding(source_id="semgrep", kind="scanner", vendor="semgrep", rc="warn")
    run1 = _scan(target, finding)
    [row] = json.loads((run1.out_dir / "findings.json").read_text())
    assert cli_main(["suppress", row["id"], "--operator", ALICE, "--justification", "j",
                     "--run", str(run1.out_dir), "--target", str(target)]) == 0
    assert "unsigned" in capsys.readouterr().err
    run2 = _scan(target, finding)
    assert run2.exit_code == 0                                      # warn still applies it
    assert any(d["kind"] == "decisions_applied_unsigned" for d in run2.degradations)
    assert run2.manifest["prior_decisions"][0]["signature_warning"] is True
    md = (run2.out_dir / "summary.md").read_text()
    assert "WITHOUT a verified signature" in md and "Decision signatures:** warn" in md


def test_signing_key_from_env_and_config(tmp_path, keys, capsys, monkeypatch):
    target = _repo(tmp_path, "enforce")
    finding = orch_finding(source_id="semgrep", kind="scanner", vendor="semgrep", rc="env")
    run1 = _scan(target, finding)
    [row] = json.loads((run1.out_dir / "findings.json").read_text())
    t = ["--target", str(target)]
    assert cli_main(["decisions", "trust", "--principal", ALICE, "--key",
                     str(keys[ALICE][1]), *t]) == 0
    monkeypatch.setenv("SECURITY_COUNCIL_SIGNING_KEY", str(keys[ALICE][0]))
    assert cli_main(["outcome", "mark", row["id"], "--verdict", "fp", "--operator", ALICE,
                     "--run", str(run1.out_dir), *t]) == 0
    assert "signed" in capsys.readouterr().out
    monkeypatch.delenv("SECURITY_COUNCIL_SIGNING_KEY")
    (target / ".security-council.yaml").write_text(
        f"decisions:\n  require_signatures: enforce\n  signing_key: {keys[ALICE][0]}\n")
    assert cli_main(["baseline", "set", "--run", str(run1.out_dir), "--operator", ALICE, *t]) == 0
    assert "(signed)" in capsys.readouterr().out
    assert cli_main(["baseline", "show", *t]) == 0
    assert json.loads(capsys.readouterr().out)["signature"] == "verified"


def test_doctor_reports_verifier(capsys):
    assert cli_main(["doctor"]) == 0
    assert "ssh-keygen" in capsys.readouterr().out


def test_mcp_signing_key_passthrough(tmp_path, keys, monkeypatch):
    from security_council import mcp_server as srv
    target = _repo(tmp_path, "enforce")
    monkeypatch.setenv(srv.ROOT_ENV, str(target))
    monkeypatch.delenv(srv.NESTED_ENV, raising=False)
    finding = orch_finding(source_id="semgrep", kind="scanner", vendor="semgrep", rc="mcp")
    run1 = _scan(target, finding)
    [row] = json.loads((run1.out_dir / "findings.json").read_text())
    dec.DecisionStore(target / ".security-council").add_trusted_signer(
        principal=ALICE, pubkey_text=keys[ALICE][1].read_text(), now_iso=NOW)
    with pytest.raises(ValueError, match="must be signed"):
        srv.sc_suppress({"finding_id": row["id"], "operator": ALICE, "justification": "j"})
    out = srv.sc_suppress({"finding_id": row["id"], "operator": ALICE, "justification": "j",
                           "signing_key": str(keys[ALICE][0])})
    assert out["signed"] is True
    audit = srv.sc_decisions_verify({})
    assert audit["summary"]["verified"] == 1 and audit["policy_resolution"]["effective"] == "enforce"


# --------------------------------------------------------------------- #
# R13 (own adversarial pass while council ran)
# --------------------------------------------------------------------- #

def test_pasted_verified_event_from_another_record_is_invalid(tmp_path, keys):
    """Attack: take alice's REAL signed suppression event for root cause A and
    paste it into record B's history (same store, same trusted signer). The
    signature verifies as bytes — but the signed root_cause is A's."""
    from tests.test_cluster import mk
    store = _store(tmp_path, keys, ALICE)
    a = _finding()
    b = mk(path="app/other.py", cwe="CWE-79", family="xss", source_id="semgrep",
           source_kind="scanner", vendor="semgrep")
    assert a.fingerprints.root_cause != b.fingerprints.root_cause
    _signed_suppress(store, keys, a)
    ev = json.loads(store._path(a.fingerprints.root_cause).read_text())["history"][-1]
    rec_b = {"schema_version": 1, "root_cause": b.fingerprints.root_cause,
             "finding_id": b.id, "title": b.title, "context_hash": b.fingerprints.context_hash,
             "history": [ev],
             "suppression": {"lifecycle": "suppressed", "status": "active", "shadow": False,
                             "decided_by": {"kind": "human", "decided_at": NOW,
                                            "operator": ALICE},
                             "decision_ref": f"decision:root_cause:{b.fingerprints.root_cause}",
                             "expires_at": ev["expires_at"],
                             "sarif_suppression": {"kind": "external", "status": "accepted",
                                                   "justification": "pasted"},
                             "vex_status": None, "vex_justification": None}}
    store._path(b.fingerprints.root_cause).write_text(json.dumps(rec_b))
    status, detail = store.verify_event(ev, expect={"root_cause": b.fingerprints.root_cause})
    assert status == "invalid" and "does not belong" in detail
    fb = mk(path="app/other.py", cwe="CWE-79", family="xss", source_id="semgrep",
            source_kind="scanner", vendor="semgrep")
    [act] = _replay(store, fb, "enforce")
    assert act["action"] == "refused_signature" and act["signature"] == "invalid"
    assert fb.disposition.lifecycle == "open"
    # a pasted outcome mark likewise does not feed the score under enforce
    store.mark_outcome(root_cause=a.fingerprints.root_cause, finding_id=a.id,
                       verdict="false_positive", operator=ALICE, now_iso=NOW,
                       signer=dec.Signer(key_path=str(keys[ALICE][0])))
    mark = json.loads(store._path(a.fingerprints.root_cause).read_text())["history"][-1]
    rec_b["history"].append(mark)
    store._path(b.fingerprints.root_cause).write_text(json.dumps(rec_b))
    counts = store.history_counts(signature_policy="enforce")
    assert b.fingerprints.root_cause not in counts
    assert counts[a.fingerprints.root_cause]["confirmed_fp"] == 1
    # control: signing off, the pasted suppression applies
    fb = mk(path="app/other.py", cwe="CWE-79", family="xss", source_id="semgrep",
            source_kind="scanner", vendor="semgrep")
    assert _replay(store, fb, "off")[0]["action"] == "reapplied_suppressed"


def test_latest_human_event_is_authoritative_not_the_block_pointer(tmp_path, keys):
    """Alice suppressed for 90 days, then re-decided with a 1-day expiry (both
    signed). Attacker points the mutable block at the older, longer event."""
    store = _store(tmp_path, keys, ALICE)
    _signed_suppress(store, keys, _finding(), days=90, now=NOW)
    later_decision = "2026-08-23T00:00:00Z"
    _signed_suppress(store, keys, _finding(), days=1, now=later_decision)  # expires 08-24
    path = store._path(_finding().fingerprints.root_cause)
    rec = json.loads(path.read_text())
    assert [e["kind"] for e in rec["history"]] == ["human_suppressed", "human_suppressed"]
    rec["suppression"]["decided_by"]["decided_at"] = NOW              # point at event 1
    rec["suppression"]["expires_at"] = rec["history"][0]["expires_at"]
    path.write_text(json.dumps(rec))
    f = _finding()                                                    # control first:
    assert _replay(store, f, "off")[0]["action"] == "reapplied_suppressed"   # block wins
    f = _finding()
    [a] = _replay(store, f, "enforce")                                # LATER = 08-25
    assert a["action"] == "reopened_expired" and a["signature"] == "verified"


def test_scan_require_signatures_flag_overrides_config(tmp_path, monkeypatch):
    from types import SimpleNamespace

    from security_council import cli
    target = _repo(tmp_path, "off")
    seen = {}

    def fake_run_scan(target, arms, config, **kw):
        seen["cfg"] = config
        return SimpleNamespace(run_id="r", out_dir=tmp_path, exit_code=0,
                               manifest={"counts": {}}, degradations=[])
    monkeypatch.setattr(cli, "run_scan", fake_run_scan)
    monkeypatch.setattr(cli, "_build_arms", lambda names, config=None, diff=None: [])
    assert cli.main(["scan", str(target), "--arms", "semgrep", "--json"]) == 0
    assert seen["cfg"]["decisions"]["require_signatures"] == "off"    # the repo's file
    assert cli.main(["scan", str(target), "--arms", "semgrep", "--json",
                     "--ignore-repo-config", "--require-signatures", "enforce"]) == 0
    assert seen["cfg"]["decisions"]["require_signatures"] == "enforce"
    assert cli.main(["scan", str(target), "--arms", "semgrep", "--json",
                     "--ignore-repo-config"]) == 0
    assert seen["cfg"]["decisions"]["require_signatures"] == "enforce"   # defaults alone


def test_mcp_scan_accepts_require_signatures(tmp_path, monkeypatch):
    from security_council import mcp_server as srv
    target = _repo(tmp_path, "off")
    monkeypatch.setenv(srv.ROOT_ENV, str(target))
    monkeypatch.delenv(srv.NESTED_ENV, raising=False)
    finding = orch_finding(source_id="semgrep", kind="scanner", vendor="semgrep", rc="ms")
    monkeypatch.setattr(srv, "_arms", lambda names, config: [
        FakeArm("semgrep", "scanner", "semgrep", [finding])])
    out = srv.sc_scan({"arms": "semgrep", "require_signatures": "enforce"})
    m = json.loads((Path(out["out_dir"]) / "manifest.json").read_text())
    assert m["signature_policy"]["configured"] == "enforce"



# --------------------------------------------------------------------- #
# R13 council round 1 (claude): dedupe, same-context transplant, roster
# patterns, machine-replay visibility, baseline age
# --------------------------------------------------------------------- #

def test_pasted_signed_mark_counts_once(tmp_path, keys):
    """Attack: one REAL signed FP mark pasted three times into its own record
    moved the history term to the cap. Same signature bytes = one mark."""
    store = _store(tmp_path, keys, ALICE)
    f = _finding()
    rc = f.fingerprints.root_cause
    store.mark_outcome(root_cause=rc, finding_id=f.id, verdict="false_positive", operator=ALICE,
                       now_iso=NOW, signer=dec.Signer(key_path=str(keys[ALICE][0])))
    path = store._path(rc)
    rec = json.loads(path.read_text())
    mark = rec["history"][-1]
    rec["history"] += [dict(mark), dict(mark)]
    path.write_text(json.dumps(rec))
    for level in ("enforce", "warn", "off"):
        audit: list = []
        assert store.history_counts(signature_policy=level, audit=audit)[rc]["confirmed_fp"] == 1, level
    audit = []
    store.history_counts(signature_policy="enforce", audit=audit)
    assert [a["signature"] for a in audit] == ["duplicate", "duplicate"]
    # two genuinely distinct signed marks still count as two
    store.mark_outcome(root_cause=rc, finding_id=f.id, verdict="false_positive", operator=ALICE,
                       now_iso=LATER, signer=dec.Signer(key_path=str(keys[ALICE][0])))
    assert store.history_counts(signature_policy="enforce")[rc]["confirmed_fp"] == 2


def test_transplant_with_identical_context_hash_is_still_refused(tmp_path, keys):
    """claude's R13 case: two root causes can share a context_hash (the hash
    is the ±3-line window; rule/CWE are not inputs), so G8 alone would not
    catch a pasted event. The signed root_cause does."""
    from tests.test_cluster import mk
    store = _store(tmp_path, keys, ALICE)
    a = _finding()
    _signed_suppress(store, keys, a)
    ev = json.loads(store._path(a.fingerprints.root_cause).read_text())["history"][-1]
    b = mk(path="app/other.py", cwe="CWE-79", family="xss", source_id="semgrep",
           source_kind="scanner", vendor="semgrep")
    b.fingerprints = dataclasses.replace(b.fingerprints, context_hash=a.fingerprints.context_hash)
    assert b.fingerprints.root_cause != a.fingerprints.root_cause
    rec_b = {"schema_version": 1, "root_cause": b.fingerprints.root_cause, "finding_id": b.id,
             "title": b.title, "context_hash": a.fingerprints.context_hash, "history": [ev],
             "suppression": {"lifecycle": "suppressed", "status": "active", "shadow": False,
                             "decided_by": {"kind": "human", "decided_at": NOW, "operator": ALICE},
                             "decision_ref": f"decision:root_cause:{b.fingerprints.root_cause}",
                             "expires_at": ev["expires_at"],
                             "sarif_suppression": {"kind": "external", "status": "accepted",
                                                   "justification": "pasted"},
                             "vex_status": None, "vex_justification": None}}
    store._path(b.fingerprints.root_cause).write_text(json.dumps(rec_b))
    [act] = _replay(store, b, "enforce")
    assert act["action"] == "refused_signature" and act["signature"] == "invalid"
    assert b.disposition.lifecycle == "open"
    b2 = mk(path="app/other.py", cwe="CWE-79", family="xss", source_id="semgrep",
            source_kind="scanner", vendor="semgrep")
    b2.fingerprints = dataclasses.replace(b2.fingerprints, context_hash=a.fingerprints.context_hash)
    assert _replay(store, b2, "off")[0]["action"] == "reapplied_suppressed"     # control


def test_pattern_principals_are_rejected_and_hand_edits_are_flagged(tmp_path, keys, capsys):
    store = _store(tmp_path, keys, ALICE)
    for bad in ("*", "*@example", "alice?", "alice,bob", "!alice"):
        with pytest.raises(signing.SigningError, match="single token"):
            store.add_trusted_signer(principal=bad, pubkey_text=keys[ALICE][1].read_text(),
                                     now_iso=NOW)
        assert not signing.valid_principal(bad)
    clean_roster = store.allowed_signers_path.read_text()
    assert signing.roster_warnings(store.allowed_signers_path) == []
    f = _finding()
    _signed_suppress(store, keys, f)
    ev = json.loads(store._path(f.fingerprints.root_cause).read_text())["history"][-1]
    assert store.verify_event(ev)[0] == "verified"

    # a hand-edited roster that vouches for anyone vouches for no one: alice's
    # REAL signature is refused until the pattern / CA lines are removed
    pub = keys[BOB][1].read_text().split()
    with open(store.allowed_signers_path, "a") as fh:
        fh.write(f"* {pub[0]} {pub[1]}\n")
        fh.write(f"ca@example cert-authority,namespaces=\"{signing.NAMESPACE}\" {pub[0]} {pub[1]}\n")
    warns = signing.roster_warnings(store.allowed_signers_path)
    assert any("pattern" in w for w in warns) and any("cert-authority" in w for w in warns)
    assert any("namespaces=" in w for w in warns)                 # the `*` line has none
    status, detail = store.verify_event(ev)
    assert status == "invalid" and "roster refused" in detail
    assert _replay(store, _finding(), "enforce")[0]["action"] == "refused_signature"
    audit = store.verify_store(signature_policy="enforce")
    assert audit["roster_warnings"] == warns and audit["summary"]["would_refuse"] == 1
    assert cli_main(["decisions", "verify", "--target", str(tmp_path)]) == 1
    assert "⚠ roster REFUSED" in capsys.readouterr().out

    # a line WITHOUT namespaces= only warns; verification still works
    store.allowed_signers_path.write_text(clean_roster + f"{BOB} {pub[0]} {pub[1]}\n")
    assert store.verify_event(ev)[0] == "verified"
    assert all("namespaces=" in w for w in signing.roster_warnings(store.allowed_signers_path))
    assert cli_main(["decisions", "verify", "--target", str(tmp_path)]) == 0


def test_machine_replay_under_enforce_is_a_visible_degradation(tmp_path):
    target = tmp_path / "repo"
    (target / "app").mkdir(parents=True)
    (target / "app" / "x.py").write_text("q = 1\n")
    finding = orch_finding(source_id="semgrep", kind="scanner", vendor="semgrep", rc="mach")
    store = dec.DecisionStore(target / ".security-council")
    store.dir.mkdir(parents=True)
    rc = finding.fingerprints.root_cause
    rec = {"schema_version": 1, "root_cause": rc, "finding_id": finding.id, "title": finding.title,
           "context_hash": finding.fingerprints.context_hash, "history": [],
           "suppression": {"lifecycle": "suppressed", "status": "active", "shadow": False,
                           "decided_by": {"kind": "auto", "decided_at": NOW, "model_id": "m",
                                          "prompt_sha256": SHA, "panel_sha256": SHA},
                           "decision_ref": f"decision:root_cause:{rc}",
                           "expires_at": "2099-01-01T00:00:00Z",
                           "sarif_suppression": {"kind": "external", "status": "accepted",
                                                 "justification": "forged"},
                           "vex_status": None, "vex_justification": None}}
    store._path(rc).write_text(json.dumps(rec))
    arms = [FakeArm("semgrep", "scanner", "semgrep", [finding])]
    run = run_scan(target, arms, _cfg("enforce"), isolate=False)
    assert run.exit_code == 1                                       # unarmed: not replayed
    assert any(p["action"] == "ignored_machine_unarmed" for p in run.manifest["prior_decisions"])
    armed = _cfg("enforce", auto_suppress=True, accept_suppression_risk=True)
    run = run_scan(target, arms, armed, isolate=False)
    assert run.exit_code == 0                                       # the documented residual
    assert any(d["kind"] == "machine_decisions_replayed" for d in run.degradations)
    assert "machine" in (run.out_dir / "summary.md").read_text()


def test_signed_baseline_reports_its_age(tmp_path, keys):
    target = tmp_path / "repo"
    (target / "app").mkdir(parents=True)
    (target / "app" / "x.py").write_text("q = 1\n")
    finding = orch_finding(source_id="semgrep", kind="scanner", vendor="semgrep", rc="age")
    store = _store(target, keys, ALICE)
    store.set_baseline([_bl_row(finding)], run_id="r", now_iso="2026-08-01T00:00:00Z",
                       operator=ALICE, signer=dec.Signer(key_path=str(keys[ALICE][0])))
    run = run_scan(target, [FakeArm("semgrep", "scanner", "semgrep", [finding])],
                   _cfg("enforce", gate_baseline="new"), isolate=False)
    bd = run.manifest["baseline_delta"]
    assert bd["signature"] == "verified" and isinstance(bd["age_days"], int) and bd["age_days"] >= 20
    assert "days ago" in (run.out_dir / "summary.md").read_text()



# --------------------------------------------------------------------- #
# R13 council round 2 (claude D1-D3/R1/N1/N2, codex): tamper on the history
# term, audit/scan parity, canonical files, signed-time selection
# --------------------------------------------------------------------- #

def _mark(store, keys, f, verdict, now):
    store.mark_outcome(root_cause=f.fingerprints.root_cause, finding_id=f.id, verdict=verdict,
                       operator=ALICE, now_iso=now, signer=dec.Signer(key_path=str(keys[ALICE][0])))


def test_forged_clone_before_a_real_mark_cannot_shadow_it(tmp_path, keys):
    """D1: a clone carrying the real mark's signature bytes but a changed
    verdict, placed BEFORE the real mark, used to reserve the signature, fail
    verification, and get the real mark dropped as a duplicate."""
    store = _store(tmp_path, keys, ALICE)
    f = _finding()
    rc = f.fingerprints.root_cause
    _mark(store, keys, f, "true_positive", NOW)
    path = store._path(rc)
    rec = json.loads(path.read_text())
    real = rec["history"][-1]
    rec["history"] = [dict(real, verdict="false_positive"), real]
    path.write_text(json.dumps(rec))
    audit: list = []
    assert store.history_counts(signature_policy="enforce", audit=audit)[rc] == \
        {"confirmed_tp": 1, "confirmed_fp": 0}
    assert [a["signature"] for a in audit] == ["invalid"]           # the clone, not the real
    rows = [r for r in store.verify_store()["rows"] if r["kind"] == "outcome_mark"]
    assert [(r["verdict"], r["signature"]) for r in rows] == \
        [("false_positive", "invalid"), ("true_positive", "verified")]
    # control: under off the clone is simply another (unverified) mark
    assert store.history_counts()[rc] == {"confirmed_tp": 1, "confirmed_fp": 1}


def test_audit_agrees_with_scan_on_pasted_and_duplicate_marks(tmp_path, keys):
    """D2: `decisions verify` used to show a pasted or duplicated mark as
    verified while the scan refused it."""
    from tests.test_cluster import mk
    store = _store(tmp_path, keys, ALICE)
    a = _finding()
    _mark(store, keys, a, "false_positive", NOW)
    mark = json.loads(store._path(a.fingerprints.root_cause).read_text())["history"][-1]
    b = mk(path="app/other.py", cwe="CWE-79", family="xss", source_id="semgrep",
           source_kind="scanner", vendor="semgrep")
    store._path(b.fingerprints.root_cause).write_text(json.dumps(
        {"schema_version": 1, "root_cause": b.fingerprints.root_cause, "finding_id": b.id,
         "title": b.title, "context_hash": b.fingerprints.context_hash,
         "history": [mark, dict(mark)]}))
    rows = [r for r in store.verify_store()["rows"] if r["kind"] == "outcome_mark"]
    by_rec = {}
    for r in rows:
        by_rec.setdefault(r["record"], []).append((r["signature"], r["applies"]))
    assert by_rec[store._path(a.fingerprints.root_cause).name] == [("verified", True)]
    assert by_rec[store._path(b.fingerprints.root_cause).name] == \
        [("invalid", False), ("invalid", False)]
    assert b.fingerprints.root_cause not in store.history_counts(signature_policy="enforce")
    # and a genuine duplicate in the right record shows as such in the audit
    rec = json.loads(store._path(a.fingerprints.root_cause).read_text())
    rec["history"].append(dict(mark))
    store._path(a.fingerprints.root_cause).write_text(json.dumps(rec))
    rows = [r for r in store.verify_store()["rows"]
            if r["kind"] == "outcome_mark" and r["record"] == store._path(a.fingerprints.root_cause).name]
    assert [(r["signature"], r["applies"]) for r in rows] == [("verified", True), ("duplicate", False)]


def test_noncanonical_record_file_cannot_override_a_root_cause(tmp_path, keys):
    """D3: a second file claiming an existing root cause used to REPLACE that
    root cause's counts (assignment, sorted-last wins)."""
    store = _store(tmp_path, keys, ALICE)
    f = _finding()
    rc = f.fingerprints.root_cause
    _mark(store, keys, f, "true_positive", NOW)
    _mark(store, keys, f, "true_positive", LATER)
    rec = json.loads(store._path(rc).read_text())
    rogue = dict(rec, history=[rec["history"][0]])              # a subset, in a rogue file
    (store.dir / ("f" * 32 + ".json")).write_text(json.dumps(rogue))
    audit: list = []
    assert store.history_counts(signature_policy="enforce", audit=audit)[rc]["confirmed_tp"] == 2
    assert any(a["signature"] == "noncanonical_record" for a in audit)
    assert store.history_counts()[rc]["confirmed_tp"] == 2           # off too: file-level rule
    rows = store.verify_store()["rows"]
    assert any(r["signature"] == "noncanonical_record" and r["record"].startswith("f" * 32)
               for r in rows)
    # replay ignores the rogue file as well: it is looked up by slug, never globbed
    f2 = _finding()
    assert _replay(store, f2, "enforce") == []                      # no suppression exists


def test_reordering_signed_events_does_not_pick_the_older_one(tmp_path, keys):
    """R1: array position is as writable as the block pointer. The event
    with the greatest SIGNED `at` among verifying events governs."""
    store = _store(tmp_path, keys, ALICE)
    _signed_suppress(store, keys, _finding(), days=90, now=NOW)
    _signed_suppress(store, keys, _finding(), days=1, now="2026-08-23T00:00:00Z")
    path = store._path(_finding().fingerprints.root_cause)
    rec = json.loads(path.read_text())
    rec["history"].reverse()                                       # 1-day event now first
    rec["suppression"]["expires_at"] = rec["history"][-1]["expires_at"]   # block says 90d
    path.write_text(json.dumps(rec))
    f = _finding()
    assert _replay(store, f, "off")[0]["action"] == "reapplied_suppressed"    # control
    f = _finding()
    [a] = _replay(store, f, "enforce")
    assert a["action"] == "reopened_expired" and a["signature"] == "verified"
    # and an unsigned event with a far-future `at` appended last is ignored in
    # favour of the verifying ones (fail-safe either way)
    rec = json.loads(path.read_text())
    rec["suppression"]["status"] = "active"
    rec["history"].append({**rec["history"][0], "at": "2099-01-01T00:00:00Z",
                           "expires_at": "2099-06-01T00:00:00Z", "signature": None})
    path.write_text(json.dumps(rec))
    f = _finding()
    [a] = _replay(store, f, "enforce")
    assert a["action"] == "reopened_expired" and a["signature"] == "verified"


def test_principal_trailing_newline_and_bare_decisions_key(tmp_path, monkeypatch):
    assert not signing.valid_principal("alice@example\n")           # N1: fullmatch
    (tmp_path / "op.yaml").write_text("decisions:\n")                 # N2: bare key -> None
    cfg = load_config(tmp_path, explicit=tmp_path / "op.yaml")
    assert cfg["decisions"]["require_signatures"] == "enforce"
    from types import SimpleNamespace

    from security_council import cli
    seen = {}
    monkeypatch.setattr(cli, "run_scan", lambda t, a, c, **kw: (
        seen.__setitem__("cfg", c) or SimpleNamespace(run_id="r", out_dir=tmp_path, exit_code=0,
                                                       manifest={"counts": {}}, degradations=[])))
    monkeypatch.setattr(cli, "_build_arms", lambda names, config=None, diff=None: [])
    assert cli.main(["scan", str(tmp_path), "--arms", "semgrep", "--json", "--config",
                     str(tmp_path / "op.yaml"), "--require-signatures", "warn"]) == 0
    assert seen["cfg"]["decisions"]["require_signatures"] == "warn"


def test_refused_marks_and_rosters_are_scan_degradations(tmp_path, keys):
    target = tmp_path / "repo"
    (target / "app").mkdir(parents=True)
    (target / "app" / "x.py").write_text("q = 1\n")
    finding = orch_finding(source_id="semgrep", kind="scanner", vendor="semgrep", rc="deg")
    store = _store(target, keys, ALICE)
    store.mark_outcome(root_cause=finding.fingerprints.root_cause, finding_id=finding.id,
                       verdict="false_positive", operator=ALICE, now_iso=NOW)   # unsigned
    arms = [FakeArm("semgrep", "scanner", "semgrep", [finding])]
    run = run_scan(target, arms, _cfg("enforce"), isolate=False)
    assert any(d["kind"] == "outcome_marks_refused" for d in run.degradations)
    assert run.manifest["history_audit"][0]["signature"] == "unsigned"
    pub = keys[BOB][1].read_text().split()
    with open(store.allowed_signers_path, "a") as fh:
        fh.write(f"* {pub[0]} {pub[1]}\n")
    run = run_scan(target, arms, _cfg("enforce"), isolate=False)
    assert any(d["kind"] == "roster_refused" for d in run.degradations)
    # a rogue record file is its own degradation, not a "refused mark"
    (store.dir / ("e" * 32 + ".json")).write_text(json.dumps(
        {"schema_version": 1, "root_cause": finding.fingerprints.root_cause, "history": []}))
    run = run_scan(target, arms, _cfg("enforce"), isolate=False)
    kinds = [d["kind"] for d in run.degradations]
    assert "records_ignored" in kinds
    assert sum(1 for d in run.degradations if d["kind"] == "outcome_marks_refused") == 1
    assert "e" * 32 in next(d["detail"] for d in run.degradations if d["kind"] == "records_ignored")



# --------------------------------------------------------------------- #
# R13 council round 3 (claude): armor variants, block-kind flip, roster
# option parsing, same-instant tiebreak
# --------------------------------------------------------------------- #

def test_whitespace_variants_of_one_signature_count_once(tmp_path, keys):
    """ssh-keygen accepts a stripped trailing newline and re-wrapped base64
    as the same armor; keying the dedupe on the string let one real mark
    count twice under enforce (and `decisions verify` showed both applied)."""
    store = _store(tmp_path, keys, ALICE)
    f = _finding()
    rc = f.fingerprints.root_cause
    _mark(store, keys, f, "false_positive", NOW)
    path = store._path(rc)
    rec = json.loads(path.read_text())
    real = rec["history"][-1]
    armored = real["signature"]["sig"]
    body = "".join(ln for ln in armored.splitlines()
                   if not ln.startswith("-----"))
    rewrapped = ("-----BEGIN SSH SIGNATURE-----\n"
                 + "\n".join(body[i:i + 40] for i in range(0, len(body), 40))
                 + "\n-----END SSH SIGNATURE-----\n")
    variants = [json.loads(json.dumps(real)) for _ in range(2)]
    variants[0]["signature"]["sig"] = armored.rstrip("\n")
    variants[1]["signature"]["sig"] = rewrapped
    for v in variants:                                   # each variant verifies on its own
        assert store.verify_event(v, expect={"root_cause": rc})[0] == "verified"
    rec["history"] += variants
    path.write_text(json.dumps(rec))
    audit: list = []
    assert store.history_counts(signature_policy="enforce", audit=audit)[rc]["confirmed_fp"] == 1
    assert [a["signature"] for a in audit] == ["duplicate", "duplicate"]
    rows = [r for r in store.verify_store()["rows"] if r["kind"] == "outcome_mark"]
    assert [r["applies"] for r in rows] == [True, False, False]


def test_block_kind_flipped_to_auto_still_takes_the_human_path(tmp_path, keys):
    """A record with a real signed human decision whose block `decided_by.kind`
    is edited to "auto" (with plausible machine fields) used to take the
    unverified machine path in an armed repo."""
    store = _store(tmp_path, keys, ALICE)
    _signed_suppress(store, keys, _finding(), days=1)              # expires before LATER
    path = store._path(_finding().fingerprints.root_cause)
    rec = json.loads(path.read_text())
    rec["suppression"]["decided_by"] = {"kind": "auto", "decided_at": NOW, "model_id": "m",
                                        "prompt_sha256": SHA, "panel_sha256": SHA}
    rec["suppression"]["expires_at"] = "2099-01-01T00:00:00Z"
    path.write_text(json.dumps(rec))
    f = _finding()
    [a] = _replay(store, f, "enforce", machine_replay=True)       # armed: worst case
    assert a["action"] == "reopened_expired" and a["signature"] == "verified"
    f = _finding()
    rec = json.loads(path.read_text())
    rec["suppression"]["status"] = "active"
    human = next(e for e in rec["history"] if e["kind"].startswith("human_"))
    human["justification"] = "edited"                             # break the human event
    path.write_text(json.dumps(rec))
    [a] = _replay(store, f, "enforce", machine_replay=True)
    assert a["action"] == "refused_signature"                     # never the machine path


def test_cert_authority_is_an_option_not_a_substring(tmp_path, keys):
    store = _store(tmp_path, keys, ALICE)
    pub = keys[BOB][1].read_text().split()
    with open(store.allowed_signers_path, "a") as fh:
        fh.write(f'{BOB} namespaces="{signing.NAMESPACE}" {pub[0]} {pub[1]} '
                 f"cert-authority-team-laptop\n")               # comment only
    assert [s for s, _ in signing.roster_problems(store.allowed_signers_path)] == []
    with open(store.allowed_signers_path, "a") as fh:
        fh.write(f'ca@example cert-authority,namespaces="{signing.NAMESPACE}" {pub[0]} {pub[1]}\n')
    assert ("refuse", ) == tuple({s for s, _ in signing.roster_problems(store.allowed_signers_path)})


def test_roster_options_are_parsed_like_openssh(tmp_path, keys):
    """R13 round 4 (claude + codex): OpenSSH's option field is quote-aware —
    `namespaces="a,b c"` contains a space and a comma — and option names are
    case-insensitive. A whitespace split hid `cert-authority` behind a
    quoted space; a case-sensitive compare hid `CERT-AUTHORITY`."""
    kt, key = keys[BOB][1].read_text().split()[:2]
    ns = signing.NAMESPACE
    cases = {
        f'ca@x cert-authority,namespaces="{ns},x y" {kt} {key}': ("refuse", "cert-authority"),
        f'ca@x CERT-AUTHORITY,namespaces="{ns}" {kt} {key}': ("refuse", "cert-authority"),
        f'ca@x namespaces="{ns},x y",Cert-Authority {kt} {key} c': ("refuse", "cert-authority"),
        f'{BOB} namespaces="{ns},x y" {kt} {key}': None,               # quoted space, fine
        f'ca@x "cert-authority",namespaces="{ns}" {kt} {key}': ("refuse", "cert-authority"),
        f'ca@x\tcert-authority,namespaces="{ns}"\t{kt} {key}': ("refuse", "cert-authority"),
        f'ca@x  cert-authority, {kt} {key}': ("refuse", "cert-authority"),
        f'{BOB} valid-after="20260101",namespaces="{ns}" {kt} {key}': None,
        f'{BOB} {kt} {key} cert-authority,namespaces="{ns}"': ("warn", "namespaces"),  # comment
    }
    for line, expect in cases.items():
        principal, opts = signing.parse_roster_line(line)
        assert principal in (BOB, "ca@x"), line
        probs = signing.roster_problems(_roster(tmp_path, line))
        if expect is None:
            assert probs == [], line
        else:
            sev, needle = expect
            assert any(p[0] == sev and needle in p[1] for p in probs), (line, probs)
            if sev == "warn":
                assert not any(p[0] == "refuse" for p in probs), (line, probs)
    # and ssh-keygen itself accepts the quoted-space line as a trust anchor,
    # so the refusal has to see what ssh-keygen sees
    roster = _roster(tmp_path, f'{ALICE} namespaces="{ns},x y" '
                               + " ".join(keys[ALICE][1].read_text().split()[:2]))
    payload = signing.canonical({"q": 1})
    sig = signing.sign(payload, key_path=keys[ALICE][0])
    assert signing.verify(payload, sig, allowed_signers=roster, principal=ALICE)[0] == "verified"
    roster = _roster(tmp_path, f'{ALICE} CERT-AUTHORITY,namespaces="{ns}" '
                               + " ".join(keys[ALICE][1].read_text().split()[:2]))
    assert signing.verify(payload, sig, allowed_signers=roster,
                          principal=ALICE)[1].startswith("roster refused")


def _roster(tmp_path, line):
    p = tmp_path / f"roster-{abs(hash(line))}"
    p.write_text(line + "\n")
    return p


def test_signed_event_with_unparseable_at_is_not_verified(tmp_path, keys):
    """A trusted signer could sign `at: "yesterday"`; it must not govern and
    must not be reported as verified (the record is refused, fail-safe)."""
    store = _store(tmp_path, keys, ALICE)
    f = _finding()
    with pytest.raises(ValueError):                                # the CLI path can't
        _signed_suppress(store, keys, f, now="yesterday")
    # so forge the shape a buggy producer could write: sign it directly
    event = {"at": "yesterday", "kind": "human_suppressed", "lifecycle": "suppressed",
             "operator": ALICE, "finding_id": f.id, "root_cause": f.fingerprints.root_cause,
             "context_hash": f.fingerprints.context_hash, "justification": "j",
             "expires_at": "2099-01-01T00:00:00Z", "vex_justification": None,
             "store_id": store.store_id()}
    store._sign_event(event, dec.Signer(key_path=str(keys[ALICE][0])), now_iso=NOW)
    rec = {"schema_version": 1, "root_cause": f.fingerprints.root_cause, "finding_id": f.id,
           "title": f.title, "context_hash": f.fingerprints.context_hash, "history": [event],
           "suppression": {"lifecycle": "suppressed", "status": "active", "shadow": False,
                           "decided_by": {"kind": "human", "decided_at": NOW, "operator": ALICE},
                           "decision_ref": f"decision:root_cause:{f.fingerprints.root_cause}",
                           "expires_at": "2099-01-01T00:00:00Z", "sarif_suppression": {},
                           "vex_status": None, "vex_justification": None}}
    store.dir.mkdir(parents=True, exist_ok=True)
    store._path(f.fingerprints.root_cause).write_text(json.dumps(rec))
    ev, status, detail = store._authoritative_human_event(rec, root_cause=f.fingerprints.root_cause)
    assert status == "invalid" and "timestamp" in detail
    [a] = _replay(store, _finding(), "enforce")
    assert a["action"] == "refused_signature"


def test_same_instant_decisions_prefer_the_shorter_lived_one(tmp_path, keys):
    store = _store(tmp_path, keys, ALICE)
    _signed_suppress(store, keys, _finding(), days=90, now=NOW)
    _signed_suppress(store, keys, _finding(), days=1, now=NOW)     # same `at`
    path = store._path(_finding().fingerprints.root_cause)
    rec = json.loads(path.read_text())
    rec["history"].reverse()                                       # order must not matter
    path.write_text(json.dumps(rec))
    f = _finding()
    [a] = _replay(store, f, "enforce")
    assert a["action"] == "reopened_expired"                       # the 1-day one governs
