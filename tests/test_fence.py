"""M-V4a fence: the orchestrator bwrap sandbox is certifiable HERE (bwrap on
PATH), the canary actually blocks escapes, and the env allowlist drops tokens."""

import pytest

from security_council import fence

_HAVE_BWRAP = fence.bwrap_available()[0]
requires_bwrap = pytest.mark.skipif(not _HAVE_BWRAP, reason="bwrap not installed")


def test_bwrap_argv_binds_only_the_work_copy():
    argv = fence.bwrap_argv(work_dir="/tmp/sc-ws/work", home="/tmp/sc-ws/home")
    assert "--unshare-net" in argv                 # no network by default
    assert "--die-with-parent" in argv             # grandchildren die with parent
    # writable binds: only the work dir + tmpfs home; system dirs are ro-bind
    assert argv[argv.index("--bind") + 1] == "/tmp/sc-ws/work"
    assert "--ro-bind" in argv and "--tmpfs" in argv


@requires_bwrap
def test_certify_mints_certificate_and_canary_blocks_escapes(tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    original = tmp_path / "original"      # stands in for the real repo
    original.mkdir()
    cert, report = fence.certify(work_dir=work, original=original)
    assert cert is not None, report
    assert report["breaches"] == [] and report["canary_done"] is True
    assert cert.live() and cert.config_hash and cert.bwrap_version
    # the canary tried to write <original>/.sc-canary and it must NOT exist
    assert not (original / ".sc-canary").exists()


@requires_bwrap
def test_fenced_process_cannot_write_outside_work_or_reach_home(tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    home = tmp_path / "home"
    home.mkdir()
    outside = tmp_path / "outside" / "escape.txt"
    (tmp_path / "outside").mkdir()
    r = fence.run_in_fence(["/bin/sh", "-c", f"touch {outside} 2>&1; echo done"],
                           work_dir=work, home=home)
    assert "done" in r.stdout
    assert not outside.exists()             # write outside the work bind blocked
    # but writing inside the work copy works
    r2 = fence.run_in_fence(["/bin/sh", "-c", "touch ./inside.txt && echo ok"],
                            work_dir=work, home=home)
    assert (work / "inside.txt").exists() and "ok" in r2.stdout


def test_certify_refuses_without_bwrap(tmp_path, monkeypatch):
    monkeypatch.setattr(fence, "bwrap_available", lambda: (False, "not installed"))
    cert, report = fence.certify(work_dir=tmp_path, original=tmp_path)
    assert cert is None and "refused" in report


def test_fence_certificate_expires():
    import time
    cert = fence.FenceCertificate(config_hash="h", bwrap_version="v", host="x",
                                  minted_at=time.time() - fence.FENCE_TTL_SECONDS - 1)
    assert not cert.live()


def test_allowlisted_env_drops_tokens_keeps_vendor(monkeypatch):
    for k in ("AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "GITLAB_TOKEN",
              "SYSTEM_ACCESSTOKEN", "NPM_TOKEN", "KUBECONFIG", "SSH_AUTH_SOCK"):
        monkeypatch.setenv(k, "sensitive")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "vendor-ok")
    monkeypatch.setenv("PATH", "/usr/bin")
    env = fence.allowlisted_env(home="/tmp/h")
    assert env["ANTHROPIC_API_KEY"] == "vendor-ok" and env["PATH"] == "/usr/bin"
    assert env["HOME"] == "/tmp/h" and env["SECURITY_COUNCIL_NESTED"] == "1"
    for k in ("AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "GITLAB_TOKEN",
              "SYSTEM_ACCESSTOKEN", "NPM_TOKEN", "KUBECONFIG", "SSH_AUTH_SOCK"):
        assert k not in env


def test_bwrap_is_present_on_this_machine():
    # documents the R6 finding that the fence is certifiable here
    assert _HAVE_BWRAP, "expected bubblewrap installed for the fix-lane fence"


# --------------------------------------------------------------------- #
# B1: relaxed posture — neutral-path runtime binds + declared open network
# --------------------------------------------------------------------- #

def test_bwrap_argv_carries_runtime_binds_and_open_network():
    argv = fence.bwrap_argv(work_dir="/w", home="/h", allow_network=True,
                            runtime_binds=(("/real/claude", "/opt/sc-vendor/bin/claude"),))
    assert "--unshare-net" not in argv                     # network declared open
    # the runtime is bound at its NEUTRAL sandbox path, never its real path
    joined = " ".join(argv)
    assert "--ro-bind /real/claude /opt/sc-vendor/bin/claude" in joined


def test_runtime_bind_is_part_of_the_hashed_shape():
    base = fence.config_hash_for(work_dir="/w", home="/h", allow_network=True)
    withrt = fence.config_hash_for(work_dir="/w", home="/h", allow_network=True,
                                   runtime_binds=(("/real/x", "/opt/sc-vendor/bin/x"),))
    assert base != withrt                                  # a different runtime re-certifies
    # network posture is also part of the shape (strict != relaxed)
    assert fence.config_hash_for(work_dir="/w", home="/h", allow_network=False) != base


def test_resolve_runtime_elf_and_unknown(tmp_path, monkeypatch):
    elf = tmp_path / "bin" / "toolx"
    elf.parent.mkdir()
    elf.write_bytes(b"\x7fELF" + b"\x00" * 40)
    monkeypatch.setattr(fence.shutil, "which", lambda c: str(elf) if c == "toolx" else None)
    plan = fence.resolve_runtime("toolx")
    assert plan is not None and plan.provenance["kind"] == "elf"
    assert plan.binds == ((str(elf), "/opt/sc-vendor/bin/toolx"),)
    assert plan.path_dirs == ("/opt/sc-vendor/bin",) and plan.provenance["sha256"]
    assert fence.resolve_runtime("nope") is None           # not on PATH -> refuse


def test_resolve_runtime_node_script(tmp_path, monkeypatch):
    root = tmp_path / "node" / "v1"
    (root / "bin").mkdir(parents=True)
    (root / "lib" / "node_modules" / "toolz" / "bin").mkdir(parents=True)
    node = root / "bin" / "node"
    node.write_bytes(b"\x7fELF" + b"\x00" * 40)
    script = root / "lib" / "node_modules" / "toolz" / "bin" / "toolz.js"
    script.write_text("#!/usr/bin/env node\nconsole.log('x')\n")
    def which(c):
        return {"toolz": str(script), "node": str(node)}.get(c)
    monkeypatch.setattr(fence.shutil, "which", which)
    plan = fence.resolve_runtime("toolz")
    assert plan is not None and plan.provenance["kind"] == "node"
    assert plan.binds == ((str(root), "/opt/sc-node"),)    # whole node root
    assert plan.path_dirs == ("/opt/sc-node/bin",)


@requires_bwrap
def test_relaxed_certificate_records_waived_network(tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    cert, report = fence.certify(work_dir=work, original=tmp_path / "orig", allow_network=True)
    assert cert is not None, report
    assert report["network"] == "open:waived_by_posture"   # not silently uncounted
    assert report["breaches"] == []                        # NET_VISIBLE is not a breach here
    # a relaxed certificate cannot satisfy a strict (no-network) run
    assert fence.verify_certificate(cert, work_dir=work, home=tmp_path / "orig" / "sc-fence-home",
                                    allow_network=False) is not None


@requires_bwrap
def test_in_place_runtime_bind_breaches_home_visible_but_neutral_does_not(tmp_path):
    # B0/live proof: binding a vendor binary at its real ~/... path makes the
    # real HOME exist in the namespace (a breach); a neutral path does not.
    import os
    work = tmp_path / "work"
    work.mkdir()
    real_home = os.path.expanduser("~")
    inplace = fence.run_in_fence(
        ["/bin/sh", "-c", f"[ -e {real_home} ] && echo VIS || echo abs"],
        work_dir=work, home=tmp_path / "h1",
        runtime_binds=((f"{real_home}", f"{real_home}"),))
    assert "VIS" in inplace.stdout                          # in-place bind -> home visible
    neutral = fence.run_in_fence(
        ["/bin/sh", "-c", f"[ -e {real_home} ] && echo VIS || echo abs"],
        work_dir=work, home=tmp_path / "h2",
        runtime_binds=((f"{real_home}", "/opt/sc-vendor/bin/x"),))
    assert "abs" in neutral.stdout                          # neutral bind -> home absent
