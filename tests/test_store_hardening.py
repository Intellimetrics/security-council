"""R9 decision-store hardening: forgery regressions.

Each test here corresponds to a hole council found (and that was reproduced
live against the real CLI before the fix). The store is unsigned local state;
these are the structural defenses that do not depend on crypto.
"""

import json


from security_council import decisions as dec
from security_council import orchestrator, policy
from security_council.config import DEFAULT_CONFIG
from security_council.orchestrator import run_scan
from tests.test_cluster import mk
from tests.test_decisions import LATER, NOW, _finding, _human

RUNS = "20260824_000000"


def _ok_arm():
    from security_council.arms.base import ArmResult
    return ArmResult(name="semgrep", kind="scanner", family="semgrep", ok=True,
                     exit_code=0, error="", findings=[])


def _bl_entry(f):
    return {"id": f.id, "title": f.title, "root_cause": f.fingerprints.root_cause,
            "context_hash": f.fingerprints.context_hash,
            "path_cwe_sink": f.fingerprints.path_cwe_sink,
            "severity": f.severity.label, "uri": f.locations[0].uri}


# --------------------------------------------------------------------- #
# baseline forgery: one file used to switch the whole gate off
# --------------------------------------------------------------------- #

def test_baseline_without_digest_is_refused(tmp_path):
    """The cheapest bypass: hand-write a baseline and omit the digest."""
    store = dec.DecisionStore(tmp_path)
    f = _finding()
    forged = {"schema_version": 1, "run_id": "attacker", "set_at": NOW,
              "findings": [_bl_entry(f)]}          # note: no content_sha256
    store.baseline_path.parent.mkdir(parents=True, exist_ok=True)
    store.baseline_path.write_text(json.dumps(forged))
    assert store.load_baseline()["integrity"] == "unpinned"


def test_baseline_edited_after_set_is_detected(tmp_path):
    store = dec.DecisionStore(tmp_path)
    kept, sneaked = _finding(), mk(path="app/new.py", cwe="CWE-79", family="xss",
                                   source_id="semgrep", source_kind="scanner",
                                   vendor="semgrep")
    store.set_baseline([{"id": kept.id, "title": kept.title,
                         "fingerprints": {"root_cause": kept.fingerprints.root_cause,
                                          "context_hash": kept.fingerprints.context_hash,
                                          "path_cwe_sink": kept.fingerprints.path_cwe_sink},
                         "severity": {"label": "high"},
                         "locations": [{"uri": "app/reports.py"}]}],
                       run_id=RUNS, now_iso=NOW, operator="alice")
    assert store.load_baseline()["integrity"] == "intact"
    # attacker appends their new finding so it counts as "pre-existing"
    doc = json.loads(store.baseline_path.read_text())
    doc["findings"].append(_bl_entry(sneaked))
    store.baseline_path.write_text(json.dumps(doc))
    assert store.load_baseline()["integrity"] == "tampered"


def test_digest_is_order_independent_but_identity_sensitive(tmp_path):
    a, b = _finding(), mk(path="app/other.py", cwe="CWE-79", family="xss",
                          source_id="semgrep", source_kind="scanner", vendor="semgrep")
    e1, e2 = _bl_entry(a), _bl_entry(b)
    assert dec.baseline_content_sha256([e1, e2]) == dec.baseline_content_sha256([e2, e1])
    tweaked = dict(e2, root_cause="rootCause/v1:" + "0" * 32)
    assert dec.baseline_content_sha256([e1, e2]) != dec.baseline_content_sha256([e1, tweaked])
    # cosmetic fields are not identity: retitling must not invalidate a baseline
    assert dec.baseline_content_sha256([dict(e1, title="renamed")]) == \
        dec.baseline_content_sha256([e1])


def test_orchestrator_refuses_non_intact_baseline(tmp_path, monkeypatch):
    """End-to-end: the forged baseline that switched off the gate in a live
    reproduction must now be refused, and the run must gate again."""
    from tests.test_orchestrator import FakeArm, _finding as _of
    target = tmp_path / "repo"
    (target / "app").mkdir(parents=True)
    (target / "app" / "x.py").write_text("q = 1\n")
    finding = _of(source_id="semgrep", kind="scanner", vendor="semgrep")
    cfg = {**DEFAULT_CONFIG, "policy": {**DEFAULT_CONFIG["policy"],
                                        "gate_baseline": "new"},
           # this test is about the digest TRIPWIRE, not signatures (R13: the
           # default is now enforce, which refuses an unsigned baseline outright)
           "decisions": {**DEFAULT_CONFIG["decisions"], "require_signatures": "warn"}}

    def _scan():
        return run_scan(target, [FakeArm("semgrep", "scanner", "semgrep", [finding])],
                        cfg, isolate=False)

    assert _scan().exit_code == 1                       # gates before any baseline

    # attacker hand-writes a baseline naming the finding (root causes are
    # published in every SARIF/report), omitting the integrity digest
    store = dec.DecisionStore(target / ".security-council")
    store.baseline_path.parent.mkdir(parents=True, exist_ok=True)
    store.baseline_path.write_text(json.dumps(
        {"schema_version": 1, "run_id": "attacker", "set_at": NOW,
         "findings": [_bl_entry(finding)]}))
    run = _scan()
    assert run.exit_code == 1                           # gate NOT switched off
    assert any(d["kind"] == "baseline_refused" for d in run.degradations)

    # the same edit against a legitimately-set baseline is caught as tampering
    store.set_baseline([], run_id=RUNS, now_iso=NOW, operator="alice")
    doc = json.loads(store.baseline_path.read_text())
    doc["findings"].append(_bl_entry(finding))
    store.baseline_path.write_text(json.dumps(doc))
    run = _scan()
    assert run.exit_code == 1
    assert any(d["kind"] == "baseline_refused" and "modified after" in d["detail"]
               for d in run.degradations)

    # and the legitimate path still excuses pre-existing debt
    store.set_baseline([{"id": finding.id, "title": finding.title,
                         "fingerprints": {"root_cause": finding.fingerprints.root_cause,
                                          "context_hash": finding.fingerprints.context_hash,
                                          "path_cwe_sink": finding.fingerprints.path_cwe_sink},
                         "severity": {"label": finding.severity.label},
                         "locations": [{"uri": "app/x.py"}]}],
                       run_id=RUNS, now_iso=NOW, operator="alice")
    assert _scan().exit_code == 0


# --------------------------------------------------------------------- #
# G9: unsigned operator state can never excuse crypto / critical
# --------------------------------------------------------------------- #

def test_high_assurance_predicate_covers_crypto_and_critical():
    crypto = mk(path="app/crypto_util.py", cwe="CWE-327", family="crypto",
                source_id="semgrep", source_kind="scanner", vendor="semgrep")
    critical = mk(path="app/x.py", cwe="CWE-89", family="injection", sev="critical",
                  source_id="semgrep", source_kind="scanner", vendor="semgrep")
    ordinary = mk(path="app/y.py", cwe="CWE-89", family="injection", sev="high",
                  source_id="semgrep", source_kind="scanner", vendor="semgrep")
    assert policy.high_assurance(crypto) and policy.baseline_ineligible(crypto)
    assert policy.high_assurance(critical) and policy.baseline_ineligible(critical)
    assert not policy.high_assurance(ordinary)


def test_baselined_crypto_and_critical_still_gate():
    """Even a perfectly-formed baseline cannot take these out of the gate."""
    crypto = mk(path="app/crypto_util.py", cwe="CWE-327", family="crypto",
                source_id="semgrep", source_kind="scanner", vendor="semgrep")
    critical = mk(path="app/x.py", cwe="CWE-89", family="injection", sev="critical",
                  source_id="semgrep", source_kind="scanner", vendor="semgrep")
    ordinary = mk(path="app/y.py", cwe="CWE-89", family="injection", sev="high",
                  source_id="semgrep", source_kind="scanner", vendor="semgrep")
    for f in (crypto, critical, ordinary):
        f.baseline_state = "unchanged"           # all claim to be pre-existing
    cfg = {"policy": {"fail_on_severity": "high", "gate_baseline": "new"}}
    arms = [_ok_arm()]
    code, _ = orchestrator._exit_code([ordinary], arms, cfg)
    assert code == 0                             # ordinary debt is excused
    code, _ = orchestrator._exit_code([crypto, critical, ordinary], arms, cfg)
    assert code == 1                             # crypto/critical are not


# --------------------------------------------------------------------- #
# replay path: short leash + malformed records + stale counting
# --------------------------------------------------------------------- #

def test_high_assurance_suppression_expiry_is_clamped(tmp_path):
    store = dec.DecisionStore(tmp_path)
    crypto = mk(path="app/crypto_util.py", cwe="CWE-327", family="crypto",
                source_id="semgrep", source_kind="scanner", vendor="semgrep")
    store.record_human_decision(
        root_cause=crypto.fingerprints.root_cause,
        context_hash=crypto.fingerprints.context_hash, finding_id=crypto.id,
        title=crypto.title, operator="alice", justification="reviewed",
        now_iso=NOW, expires_days=90)
    fresh = mk(path="app/crypto_util.py", cwe="CWE-327", family="crypto",
               source_id="semgrep", source_kind="scanner", vendor="semgrep")
    actions = store.apply_prior_decisions([fresh], now_iso=LATER)
    a = actions[0]
    assert a["action"] == "reapplied_suppressed" and a["high_assurance"] is True
    assert a["expiry_clamped"] is True
    # 30 days from the decision, not the stored 90
    assert a["expires_at"].startswith("2026-09-21")
    assert fresh.disposition.expires_at == a["expires_at"]


def test_high_assurance_suppression_reopens_after_the_short_window(tmp_path):
    store = dec.DecisionStore(tmp_path)
    crypto = mk(path="app/crypto_util.py", cwe="CWE-327", family="crypto",
                source_id="semgrep", source_kind="scanner", vendor="semgrep")
    store.record_human_decision(
        root_cause=crypto.fingerprints.root_cause,
        context_hash=crypto.fingerprints.context_hash, finding_id=crypto.id,
        title=crypto.title, operator="alice", justification="reviewed",
        now_iso=NOW, expires_days=90)
    fresh = mk(path="app/crypto_util.py", cwe="CWE-327", family="crypto",
               source_id="semgrep", source_kind="scanner", vendor="semgrep")
    # day 45: inside the stored 90-day expiry, past the 30-day high-assurance cap
    actions = store.apply_prior_decisions([fresh], now_iso="2026-10-06T00:00:00Z")
    assert actions[0]["action"] == "reopened_expired"
    assert fresh.disposition.lifecycle == "reopened"
    assert "high_assurance" in fresh.disposition.reopen_reason


def test_ordinary_suppression_keeps_its_full_expiry(tmp_path):
    store = dec.DecisionStore(tmp_path)
    _human(store, _finding())
    f = _finding()
    a = store.apply_prior_decisions([f], now_iso=LATER)[0]
    assert a["expiry_clamped"] is False and a["expires_at"] == "2026-11-20T00:00:00Z"


def test_malformed_record_degrades_instead_of_crashing_the_scan(tmp_path):
    store = dec.DecisionStore(tmp_path)
    f = _finding()
    _human(store, _finding())
    rec = store.load(f.fingerprints.root_cause)
    rec["suppression"]["decided_by"]["bogus_field"] = "injected"
    dec._atomic_write(store._path(f.fingerprints.root_cause), rec)
    actions = store.apply_prior_decisions([f], now_iso=LATER)   # must not raise
    assert actions[0]["action"] == "ignored_malformed"
    assert f.disposition.lifecycle == "open"                    # not applied = safe
    assert any(h["kind"] == "malformed"
               for h in store.load(f.fingerprints.root_cause)["history"])


def test_reapply_count_accumulates_for_stale_detection(tmp_path):
    store = dec.DecisionStore(tmp_path)
    _human(store, _finding())
    for expected in (1, 2, 3):
        a = store.apply_prior_decisions([_finding()], now_iso=LATER)[0]
        assert a["reapplied_count"] == expected


# --------------------------------------------------------------------- #
# shadow counter cross-check
# --------------------------------------------------------------------- #

def test_shadow_counter_is_min_of_stored_and_observed(tmp_path):
    class _Store:
        def armed_runs_completed(self, config):
            return 99                                    # forged counter
    runs = tmp_path / "runs"
    (runs / "20260824_000001").mkdir(parents=True)
    (runs / "20260824_000001" / "manifest.json").write_text("{}")
    out_dir = runs / "20260824_000002"
    n = orchestrator._shadow_runs_completed(_Store(), {}, out_dir, "20260824_000002")
    assert n == 1                                        # evidence on disk wins
    for _ in range(10):
        pass
    assert orchestrator._shadow_runs_completed(_Store(), {}, tmp_path / "nope" / "x", "y") == 0


# --------------------------------------------------------------------- #
# reporting: provenance, not assurance
# --------------------------------------------------------------------- #

def test_report_lists_every_reapplied_suppression_individually():
    from security_council.export import markdown
    manifest = {
        "run_id": "r1", "counts": {"total": 0, "by_severity": {}, "by_state": {}},
        "arms": [], "degradations": [], "reports": [], "exit_code": 0,
        "prior_decisions": [
            {"finding_id": "abc123", "action": "reapplied_suppressed", "ref": "r",
             "title": "Weak cipher in token signing", "severity": "high",
             "operator": "alice", "decided_at": "2026-08-01T00:00:00Z",
             "expires_at": "2026-08-31T00:00:00Z", "expiry_clamped": True,
             "reapplied_count": 7, "high_assurance": True},
        ],
    }
    md = markdown.to_markdown([], manifest)
    assert "Suppressions reapplied from the decision store" in md
    assert "abc123" in md and "alice" in md and "Weak cipher" in md
    assert "2026-08-01" in md and "2026-08-31" in md
    assert "stale" in md and "high-assurance" in md          # 7 reapplies, clamped
    assert "expiry shortened" in md
    assert "✅" not in md and "verified" not in md.lower()   # provenance, not assurance


def test_report_surfaces_ignored_malformed_records():
    from security_council.export import markdown
    manifest = {"run_id": "r1", "counts": {"total": 0, "by_severity": {}, "by_state": {}},
                "arms": [], "degradations": [], "reports": [], "exit_code": 0,
                "prior_decisions": [{"finding_id": "bad1", "action": "ignored_malformed",
                                     "ref": "r", "detail": "unexpected key"}]}
    md = markdown.to_markdown([_finding()], manifest)
    assert "bad1" in md and "IGNORED" in md


def test_baseline_provenance_is_rendered():
    from security_council.export import markdown
    manifest = {"run_id": "r1", "counts": {"total": 0, "by_severity": {}, "by_state": {}},
                "arms": [], "degradations": [], "reports": [], "exit_code": 0,
                "baseline_delta": {"baseline_run": "20260824_000000", "new": 1,
                                   "unchanged": 2, "updated": 0, "absent": 0,
                                   "integrity": "intact", "operator": "alice",
                                   "set_at": "2026-08-24T00:00:00Z",
                                   "content_sha256": "deadbeefcafe0000"}}
    md = markdown.to_markdown([_finding()], manifest)
    assert "baseline provenance" in md and "alice" in md and "deadbeefcafe" in md




def test_a_record_missing_lifecycle_degrades_instead_of_crashing(tmp_path):
    """R12 round 13: `decided_by` was constructed inside a try/except but
    `lifecycle` and `decision_ref` were read BELOW it, so a record missing
    either raised a KeyError that escaped the malformed-record handler and
    crashed the scan — the thing the handler exists to prevent."""
    import json
    from security_council.decisions import DecisionStore
    f = _finding()
    store = DecisionStore(tmp_path)
    rc = f.fingerprints.root_cause
    path = store._path(rc)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({
        "schema_version": 1, "root_cause": rc, "history": [],
        "context_hash": f.fingerprints.context_hash,     # no drift
        "suppression": {                       # no "lifecycle", no "decision_ref"
            "status": "active",
            "decided_by": {"kind": "human", "operator": "someone",
                           "decided_at": "2026-08-20T00:00:00Z"},
            "expires_at": "2099-01-01T00:00:00Z"},
    }))
    actions = store.apply_prior_decisions([f], now_iso="2026-08-25T00:00:00Z")
    assert any(a["action"] == "ignored_malformed" for a in actions)
    assert f.disposition.lifecycle == "open"       # fail-safe: stays open


def test_a_record_with_an_unreadable_date_degrades_instead_of_crashing(tmp_path):
    """R12 round 18: expires_at / decided_at were parsed BEFORE the
    malformed-record guard, so `expires_at: not-a-date` raised an uncaught
    ValueError and crashed the scan."""
    import json
    from security_council.decisions import DecisionStore
    f = _finding()
    store = DecisionStore(tmp_path)
    rc = f.fingerprints.root_cause
    path = store._path(rc)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({
        "schema_version": 1, "root_cause": rc, "history": [],
        "context_hash": f.fingerprints.context_hash,
        "suppression": {"status": "active", "lifecycle": "suppressed", "decision_ref": "ref",
                        "expires_at": "not-a-date",
                        "decided_by": {"kind": "human", "operator": "x",
                                       "decided_at": "2026-08-20T00:00:00Z"}}}))
    actions = store.apply_prior_decisions([f], now_iso="2026-08-25T00:00:00Z")
    assert any(a["action"] == "ignored_malformed" and "timestamp" in a["detail"] for a in actions)
    assert f.disposition.lifecycle == "open"
