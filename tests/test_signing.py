"""R9 signing lane: `ssh-keygen -Y` signatures over decision-store EVENTS.

Every attack test here carries an `off` control that shows the same edit
succeeding without signing, so a test cannot pass because the attack never
worked in the first place (the R12 vacuity discipline)."""
import dataclasses
import json
import shutil
import subprocess

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
    assert resolve_profile({}, "quick")["decisions"]["require_signatures"] == "auto"
    assert validate_config({"decisions": {"require_signatures": "enforce"}}) == []
    assert any("require_signatures" in p for p in
               validate_config({"decisions": {"require_signatures": "Enforce"}}))
    assert any("unknown decisions key" in p for p in validate_config({"decisions": {"sign": 1}}))
    assert any("signing_key" in p for p in validate_config({"decisions": {"signing_key": 3}}))


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
