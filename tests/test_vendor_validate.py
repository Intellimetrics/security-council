"""M-V5: vendor validate/triage as NON-INDEPENDENT advisory panel voters — they
are surfaced but can never decide a verdict or satisfy the >=2-voice quorum."""
from security_council.validate import panel
from security_council.validate.council_client import CouncilResult, PeerResult
from tests.test_validate import _cite, _finding


def _cr(votes, degraded=False):
    peers = [PeerResult(name=n, ok=True, label=lbl, stance=st, model="mdl", confidence="high",
                        blockers=["b"], evidence=cites) for n, st, lbl, cites in votes]
    return CouncilResult(ok=True, degraded=degraded, results=peers)


def _vendor(verdict, participant="codex-validate", family="codex"):
    return {"participant": participant, "family": family, "verdict": verdict, "rationale": "vendor says"}


# --------------------------------------------------------------------------- #
# the opinion is built non-independent, weightless, role=vendor
# --------------------------------------------------------------------------- #


def test_vendor_opinion_is_non_independent():
    op = panel.vendor_opinion(_vendor("true_positive"), "a" * 64)
    assert op.independent is False and op.weight == 0.0 and op.role == "vendor"
    assert op.verdict == "true_positive"
    assert panel.vendor_opinion(_vendor("no"), "a" * 64).verdict == "false_positive"


# --------------------------------------------------------------------------- #
# non-independent voters never DECIDE
# --------------------------------------------------------------------------- #


def test_vendor_cannot_flip_a_verdict():
    f = _finding()
    # two independent reals -> true_positive; a vendor 'false_positive' must NOT change it
    panel.validate_finding(f, repo_root=".",
                           runner=panel.council_client.run_council if False else _runner_reals(),
                           vendor_runner=lambda finding: [_vendor("false_positive")])
    assert f.validation.verdict == "true_positive"
    adv = f.validation.evidence_check["vendor_advisory"]
    assert adv["verdicts"] == ["false_positive"] and adv["disagrees_with_panel"] is True


def test_vendor_alone_cannot_meet_quorum():
    f = _finding()
    # only ONE independent voice + a vendor voter -> still needs_human (quorum is
    # 2 INDEPENDENT voices; the vendor doesn't count)
    cr = _cr([("claude", "for", "yes", [_cite()])])          # 1 real, others absent
    val = panel.synthesize_validation(
        f, cr, prompt_sha256="a" * 64,
        extra_opinions=[panel.vendor_opinion(_vendor("true_positive"), "a" * 64),
                        panel.vendor_opinion(_vendor("true_positive"), "a" * 64)])
    assert val.verdict == "needs_human"                       # 2 vendors don't make a quorum
    assert "codex-validate" in val.evidence_check["vendor_advisory"]["voters"]


def test_vendor_agreement_is_recorded_not_decisive():
    f = _finding()
    val = panel.synthesize_validation(
        f, _cr([("claude", "for", "no", [_cite()]), ("codex", "against", "no", [_cite()]),
                ("antigravity", "neutral", "no", [_cite()])]),
        prompt_sha256="a" * 64,
        extra_opinions=[panel.vendor_opinion(_vendor("false_positive"), "a" * 64)])
    assert val.verdict == "false_positive"                    # decided by the 3 independents
    assert val.evidence_check["vendor_advisory"]["disagrees_with_panel"] is False
    # the vendor opinion IS in the panel (surfaced), flagged non-independent
    vendor_ops = [op for op in val.panel if op.role == "vendor"]
    assert len(vendor_ops) == 1 and vendor_ops[0].independent is False


def test_no_vendor_advisory_key_without_vendors():
    f = _finding()
    val = panel.synthesize_validation(
        f, _cr([("claude", "for", "yes", [_cite()]), ("codex", "against", "yes", [_cite()])]),
        prompt_sha256="a" * 64)
    assert "vendor_advisory" not in val.evidence_check


# --------------------------------------------------------------------------- #
# the producer (make_vendor_runner) with an injected proc
# --------------------------------------------------------------------------- #


def test_vendor_runner_parses_and_degrades(monkeypatch):
    f = _finding()

    class _R:
        def __init__(self, ok, out=""):
            self.ok, self.stdout, self.stderr = ok, out, ""
    seen = {}

    def _ok(cmd, **kw):
        seen["cmd"] = cmd
        return _R(True, '{"verdict":"false_positive"}')

    runner = panel.make_vendor_runner(".", family="codex", proc_run=_ok)
    out = runner(f)
    assert out and out[0]["family"] == "codex" and out[0]["verdict"] == "false_positive"
    # live contract (2026-08-25): `codex-security validate` REJECTS --format json
    # ("validate does not support noninteractive JSON output"), so asking for it
    # made every real call fail. Never reintroduce it.
    assert "--format" not in seen["cmd"] and "json" not in seen["cmd"]
    assert seen["cmd"][:2] == ["codex-security", "validate"]
    assert "--effort" in seen["cmd"]        # upstream default is xhigh, billed per finding

    # a failed vendor call is RECORDED as absent, never silently dropped
    runner2 = panel.make_vendor_runner(".", proc_run=lambda cmd, **kw: _R(False))
    got = runner2(f)
    assert len(got) == 1 and got[0]["status"] == "absent"
    assert "unavailable" in got[0]["rationale"]


def test_absent_vendor_voter_cannot_change_the_verdict():
    """An unavailable vendor voter must be inert: same verdict, and it never
    lands in the advisory block (which would imply an opinion we never got)."""
    absent = [panel.vendor_opinion({"participant": "codex-validate", "family": "codex",
                                    "verdict": "uncertain", "status": "absent",
                                    "rationale": "vendor validate unavailable: boom"}, "p")]
    base = panel.synthesize_validation(_finding(), _runner_reals()("q", cwd="."),
                                       prompt_sha256="p")
    with_absent = panel.synthesize_validation(_finding(), _runner_reals()("q", cwd="."),
                                              prompt_sha256="p", extra_opinions=absent)
    assert with_absent.verdict == base.verdict
    assert with_absent.confidence == base.confidence
    assert "vendor_advisory" not in with_absent.evidence_check
    # ...but it IS retained in the panel, so the run can show the voter was sought
    assert any(op.status == "absent" and op.participant == "codex-validate"
               for op in with_absent.panel)


def _runner_reals():
    def run(prompt, *, cwd, mode="consensus", max_cost_usd=None, timeout=600):
        return _cr([("claude", "for", "yes", [_cite()]),
                    ("codex", "against", "no", [_cite()]),
                    ("antigravity", "neutral", "yes", [_cite()])])
    return run
