"""Fix arm (M-V4a): produce a reviewed `.patch` ARTIFACT for a finding — never
applied to the user's tree (R6, go-with-conditions).

Flow, all orchestrator-owned:
1. make two fresh copies of the target — a WORK copy the vendor agent edits and
   a PRISTINE copy to diff against (symlinks preserved, not dereferenced);
   `git init` the work copy with one baseline commit, no remotes, credentials
   disabled (M4).
2. `fence.certify()` the work copy — a bwrap canary must prove no escape, or the
   job is refused (fail-closed; no `FenceCertificate`, no run).
3. run the vendor fix skill INSIDE the fence with an allowlisted env + ephemeral
   HOME (M1/M3/MV4-11). The agent may edit files and run tests — untrusted, but
   fenced with no network and no reach outside the work copy.
4. the ORCHESTRATOR extracts the diff with the neutralized `git diff --no-index`
   (never runs git in the agent's tree — MV4-10), validates + redacts it
   (`patches.py`), and returns it as a `.patch` artifact with provenance +
   review flags. `--apply`/commit/push are never available.

Built offline (fake-proc), like the other agentic arms; the live vendor run
needs spend and degrades safely to `no_patch` / `tests_ran: false`.
"""

from __future__ import annotations

import atexit
import shutil
import signal
import threading
from pathlib import Path

from .. import entitlements as _entitlements
from .. import fence as _fence
from .. import patches as _patches
from .. import proc
from ..artifacts import Artifact, artifact_id
from .base import ArmResult

# B2 (R10 precedent, M-V3): a fix job is (vendor family, HOUSE prompt file) — NOT
# a vendor plugin/skill trigger. The R10 lesson (and B1's live codex finding) is
# that `/claude-security …` and `$fix-finding` are literal text in headless
# `-p`/`exec` mode, never reachable commands; the claude fix job used to name the
# `/claude-security suggest-patches` PLUGIN command, and plugins are on B0's
# never-copy roster. Both jobs now drive OUR own instruction (`prompts/house-fix.md`)
# through the plain CLI, exactly as the analysis lane reframed its jobs onto house
# prompts (see arms/artifact_runner.py). The producer stays a house arm.
FIX_JOBS = {
    "suggest-patches": ("claude", "house-fix.md"),
    "fix-finding": ("codex", "house-fix.md"),
}

PROMPT_DIR = Path(__file__).resolve().parent.parent / "prompts"

# --------------------------------------------------------------------------- #
# B1-residual: scratch cleanup that survives CATCHABLE termination signals.
#
# `FixArm.run` cleans its scratch (`tmp_root`, which holds the COPIED vendor
# credential at 0600) in a `finally: shutil.rmtree`. A `finally` block does NOT
# run when the process is killed by a signal, so a SIGTERM/SIGINT (a `timeout`,
# a Ctrl-C, a harness cap) mid-run leaves a `/tmp/sc-fix-*` dir with the
# credential copy behind (hit live 2026-09-01). We register every active scratch
# root and rmtree the set on SIGTERM/SIGINT and at interpreter exit, chaining any
# handler that was already installed so we do not swallow the caller's behaviour.
#
# HONEST LIMIT: SIGKILL (signal 9) and a hard crash cannot be caught by any
# process — no handler runs, so a `kill -9` (or OOM-kill) mid-run can still
# strand one scratch dir. The credential copy exists ONLY while the vendor
# process runs (it is scrubbed the instant that process returns; see `run`), so
# that residue is bounded to the live-run window, is 0600, and lives under a
# 0700 mkdtemp dir. There is no in-process defence against SIGKILL; an operator
# wrapper should prefer SIGTERM (which this catches) and reap `/tmp/sc-fix-*`.
# --------------------------------------------------------------------------- #

_SCRATCH_LOCK = threading.Lock()
_ACTIVE_SCRATCH: set[str] = set()
_CLEANUP_SIGNALS = (signal.SIGTERM, signal.SIGINT)
_handlers_installed = False


def _cleanup_all_scratch() -> None:
    with _SCRATCH_LOCK:
        paths = list(_ACTIVE_SCRATCH)
        _ACTIVE_SCRATCH.clear()
    for p in paths:
        shutil.rmtree(p, ignore_errors=True)


def _make_signal_cleanup(prev):
    def _handler(signum, frame):
        _cleanup_all_scratch()
        # chain: a previously-registered Python handler still runs (e.g. SIGINT's
        # default_int_handler raises KeyboardInterrupt); SIG_IGN stays ignored;
        # SIG_DFL / None (no prior Python handler) performs the signal's default
        # action so the exit status still reflects the signal we were sent.
        if callable(prev):
            return prev(signum, frame)
        if prev == signal.SIG_IGN:
            return None
        signal.signal(signum, signal.SIG_DFL)
        import os
        os.kill(os.getpid(), signum)
        return None
    return _handler


def _install_signal_cleanup() -> None:
    """Install the scratch-cleanup handlers once, chaining whatever was there.

    Signal handlers can only be set from the main thread; when the fix lane runs
    off the main thread (an MCP server worker, a test executor) we fall back to
    `atexit` alone rather than raising — the credential copy is scrubbed post-run
    regardless, so the signal handler is defence in depth, not the only cleanup.
    """
    global _handlers_installed
    if _handlers_installed:
        return
    atexit.register(_cleanup_all_scratch)   # normal exit / unhandled-exception exit
    try:
        for sig in _CLEANUP_SIGNALS:
            prev = signal.getsignal(sig)
            signal.signal(sig, _make_signal_cleanup(prev))
    except (ValueError, OSError):
        # not the main thread (or the platform refuses): atexit still armed
        pass
    _handlers_installed = True


def _register_scratch(path: Path) -> None:
    _install_signal_cleanup()
    with _SCRATCH_LOCK:
        _ACTIVE_SCRATCH.add(str(path))


def _unregister_scratch(path: Path) -> None:
    with _SCRATCH_LOCK:
        _ACTIVE_SCRATCH.discard(str(path))


# B1 relaxed posture: where each vendor's ephemeral config home is mounted
# inside the namespace, and the env var that points the CLI at it. Neutral,
# non-/tmp paths (codex refuses to create helper aliases under /tmp — verified
# live 2026-09-01). Nothing from the real ~/.codex / ~/.claude is bound except,
# at most, the single credential FILE (never the directory — B0).
_VENDOR_HOME = {
    "codex": ("/sc-codex", "CODEX_HOME", "auth.json"),
    "claude": ("/sc-claude", "CLAUDE_CONFIG_DIR", ".credentials.json"),
}
_CODE_DISCLOSED_TO = {"codex": "openai", "claude": "anthropic"}
# vendor API-key env vars that make a credential-file bind unnecessary (B0's
# preferred auth path — a dedicated, spend-capped key delivered via the env
# allowlist rather than a copied login file)
_VENDOR_API_KEYS = {"codex": ("OPENAI_API_KEY", "CODEX_API_KEY"),
                    "claude": ("ANTHROPIC_API_KEY",)}


def prepare_fix_copies(target: Path, tmp_root: Path) -> tuple[Path, Path]:
    """(work, pristine) fresh copies; work is a git repo with a baseline commit
    and no remotes. Symlinks preserved (not dereferenced) so an out-of-tree
    symlink target can't be pulled in and embedded in a patch (MV4-7)."""
    from ..workspace import DEFAULT_EXCLUDES
    ign = shutil.ignore_patterns(*DEFAULT_EXCLUDES)
    work, pristine = tmp_root / "work", tmp_root / "pristine"
    shutil.copytree(target, work, ignore=ign, symlinks=True, ignore_dangling_symlinks=True)
    shutil.copytree(target, pristine, ignore=ign, symlinks=True, ignore_dangling_symlinks=True)
    env = _git_env()
    git = shutil.which("git") or "git"
    for args in (["init", "-q"], ["add", "-A"],
                 ["-c", "user.email=fix@sc", "-c", "user.name=sc",
                  "commit", "-q", "-m", "baseline", "--no-verify"]):
        proc.run_command([git, *args], cwd=str(work), env=env, timeout=120,
                         success_exit_codes=tuple(range(0, 2)))
    return work, pristine


def _git_env() -> dict:
    import os
    env = dict(os.environ)
    env.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
                "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "/bin/false",
                "GIT_SSH_COMMAND": "/bin/false", "GIT_ALLOW_PROTOCOL": "none"})
    return env


class FixArm:
    kind = "fix"
    supports_diff = False

    def __init__(self, *, job: str, finding: dict, model: str | None = None,
                 max_cost_usd: float = 5.0, timeout: int = 3600,
                 allow_network: bool = False, egress_acknowledged: bool = False) -> None:
        if job not in FIX_JOBS:
            raise ValueError(f"unknown fix job {job!r}; known: {sorted(FIX_JOBS)}")
        self.job = job
        self.family, self.prompt_file = FIX_JOBS[job]
        self.finding = finding
        self.model = model
        self.max_cost_usd = float(max_cost_usd)
        self.timeout = int(timeout)
        self.name = f"{self.family}-fix:{job}"
        self.command = "claude" if self.family == "claude" else "codex"
        # B0/R19 relaxed posture: live vendor patch generation needs the network
        # (the model API), so the strict no-network fence cannot host it. The
        # relaxed posture keeps the orchestrator bwrap write-boundary + home
        # invisibility but declares the network open — gated on a double
        # opt-in the operator supplies, never the scanned repo.
        self.allow_network = bool(allow_network)
        self.egress_acknowledged = bool(egress_acknowledged)

    def available(self) -> tuple[bool, str]:
        ok, detail = _fence.bwrap_available()
        if not ok:
            return False, f"fix lane needs bwrap: {detail}"
        if not shutil.which(self.command):
            return False, f"{self.command} not on PATH"
        if not self._prompt_path().is_file():
            return False, f"house fix prompt missing: {self.prompt_file}"
        if not self.allow_network:
            # STRICT lane (unchanged): the no-network fence binds only system
            # dirs, so a vendor CLI under ~/.local/~/.nvm is invisible AND the
            # model API is unreachable. Refuse up front (R10) rather than burn
            # minutes/spend to a vague no_patch. Live generation needs the
            # relaxed posture below.
            reach, why = _fence.reachable_in_fence(self.command)
            if not reach:
                return False, (f"fix lane cannot run fenced (strict, no network): {why}. "
                               "Live vendor patch generation needs the relaxed posture "
                               "(fix.allow_network + the egress acknowledgement).")
            return True, (f"fenced (strict): bwrap {detail}; {self.command} house prompt "
                          f"{self.prompt_file}")
        # RELAXED lane: consent is required and the runtime must resolve to a
        # neutral-path bind (never in-place — that would breach HOME_VISIBLE).
        if not self.egress_acknowledged:
            return False, ("relaxed fix posture (open network) needs the operator's egress "
                           "acknowledgement; it is refused without it (repo config can never "
                           "supply it).")
        plan = _fence.resolve_runtime(self.command)
        if plan is None:
            return False, (f"cannot resolve {self.command} to a neutral-path runtime bind; "
                           "the relaxed fence will not run an unresolved runtime.")
        return True, (f"fenced (relaxed, open network): {self.command} runtime "
                      f"{plan.provenance.get('kind')} at {plan.path_dirs[0]}")

    def _prompt_path(self) -> Path:
        return PROMPT_DIR / self.prompt_file

    def _prompt(self) -> str:
        uri = (self.finding.get("locations") or [{}])[0].get("uri", "?")
        cwe = ", ".join(str(c) for c in ((self.finding.get("taxonomy") or {}).get("cwe") or [])) \
            or "the reported weakness"
        # B2 (M-V3 precedent): the instruction is OUR house prompt, not a vendor
        # plugin/skill trigger. `/claude-security …` and `$fix-finding` are just
        # literal text in `-p`/`exec` mode (R10; B1 live-found), so the job drives
        # prompts/house-fix.md through the plain CLI. `str.replace` (not `.format`)
        # so any literal braces in the prompt body are left untouched.
        template = self._prompt_path().read_text()
        return template.replace("{{CWE}}", cwe).replace("{{URI}}", uri).strip()

    def _cmd(self) -> list[str]:
        prompt = self._prompt()
        if self.family == "codex":
            # codex keeps its OWN kernel sandbox INSIDE the orchestrator fence
            # (defense in depth, B0); HOME/CODEX_HOME come from the fenced env.
            base = ["codex", "exec", "--sandbox", "workspace-write",
                    "--skip-git-repo-check", prompt]
            if self.model:
                base[2:2] = ["--model", self.model]
            return base
        # claude has no kernel sandbox flag; in the relaxed posture it runs
        # EDIT-ONLY with NO --dangerously-skip-permissions (its own help scopes
        # that flag to no-network sandboxes, which the relaxed posture is not) —
        # no Bash, no WebFetch/WebSearch (B0 cond. 2; tests come from the
        # deterministic verify lane, not the agent).
        if self.allow_network:
            cmd = ["claude", "-p", prompt, "--output-format", "json",
                   "--permission-mode", "acceptEdits",
                   "--allowedTools", "Read,Glob,Grep,Edit,Write",
                   "--disallowedTools", "Bash,WebFetch,WebSearch",
                   "--no-session-persistence", "--strict-mcp-config"]
        else:
            cmd = ["claude", "-p", prompt, "--output-format", "json",
                   "--dangerously-skip-permissions", "--no-session-persistence",
                   "--strict-mcp-config"]
        if self.model:
            cmd += ["--model", self.model]
        return cmd

    def _auth_delivery(self, tmp_root: Path) -> tuple[tuple[tuple[str, str], ...], dict, str]:
        """(writable vendor-home binds, extra env, auth_kind) for the relaxed run.

        The vendor config HOME is an orchestrator-prepared, ephemeral dir bound
        rw at a neutral path — writable so the CLI can write logs/session state
        and refresh a token WITHOUT that reaching the real home. What lands in
        it, in preference order (B0):
        - `api-key`: a vendor API key is already in the environment (the env
          allowlist carries it) — the dir stays empty, nothing from the real
          home is copied or bound.
        - `oauth-file-copy`: no key, so COPY the single credential FILE (never
          the directory — it also holds other projects' history and hooks the
          CLI executes) into the ephemeral dir.
        - `none`: neither — the CLI will fail to authenticate and produce no
          patch (fail-safe); the live leg surfaces this before spend.
        """
        import os
        mount, env_var, cred_name = _VENDOR_HOME[self.command]
        vhome = tmp_root / "vendor-home"
        vhome.mkdir(mode=0o700, exist_ok=True)
        binds = ((str(vhome), mount),)
        env = {env_var: mount}
        if any(os.environ.get(k) for k in _VENDOR_API_KEYS.get(self.command, ())):
            return binds, env, "api-key"
        src = Path.home() / (".codex" if self.command == "codex" else ".claude") / cred_name
        if src.is_file():
            shutil.copy2(src, vhome / cred_name)
            (vhome / cred_name).chmod(0o600)
            return binds, env, "oauth-file-copy"
        return binds, env, "none"

    def run(self, target: Path, out_dir: Path, *, run_id: str, collected_at: str) -> ArmResult:
        import tempfile
        target = Path(target).resolve()
        tmp_root = Path(tempfile.mkdtemp(prefix="sc-fix-"))
        # B1-residual: track this scratch root so a CATCHABLE signal (SIGTERM/
        # SIGINT) rmtrees it even though it bypasses the `finally` below.
        _register_scratch(tmp_root)
        raw_dir = Path(out_dir) / "raw" / self.name.replace(":", "_")
        raw_dir.mkdir(parents=True, exist_ok=True)
        safeguard = _entitlements.safeguard_posture_for(self.model)
        tier = _entitlements.classify_model(self.model)
        allow_net = self.allow_network
        # resolve the runtime + credential delivery for the relaxed posture
        runtime_binds: tuple[tuple[str, str], ...] = ()
        writable_binds: tuple[tuple[str, str], ...] = ()
        extra_env: dict = {}
        auth_kind = "n/a"
        plan = None
        if allow_net:
            plan = _fence.resolve_runtime(self.command)
            if plan is None:
                return self._fail(f"runtime_unresolved: cannot bind {self.command} at a "
                                  "neutral path", {"job": self.job})
            writable_binds, extra_env, auth_kind = self._auth_delivery(tmp_root)
            runtime_binds = tuple(plan.binds)
        # B1/R12: host isolation posture is a STRUCTURED stamp, never a boolean.
        # `safeguard_posture` stays the model-tier field; `posture` is host
        # isolation + egress, so the two are never conflated.
        posture = {
            "execution_boundary": "orchestrator_bwrap",
            "network_access": "unrestricted" if allow_net else "unshared",
            "egress_destination_control": "none" if allow_net else "n/a",
            "operator_acknowledged_unrestricted_egress": (self.egress_acknowledged
                                                          if allow_net else None),
            "real_home_visible": False,          # certified by the canary below
            "vendor_home": auth_kind,
            "code_disclosed_to": _CODE_DISCLOSED_TO[self.command] if allow_net else None,
            "vendor_sandbox": ("workspace-write" if self.command == "codex"
                               else ("edit-only-tools" if allow_net else "none")),
            "project_command_network": "unverified",   # only a live run can confirm
            "tests_ran": False,          # never set from vendor prose (B0 cond. 8)
            "runtime": (plan.provenance if plan else None),
        }
        cov = {"job": self.job, "safeguard_posture": safeguard, "posture": posture}
        try:
            work, pristine = prepare_fix_copies(target, tmp_root)
            # relaxed posture mounts the vendor HOME at a neutral non-/tmp path
            # (codex refuses helper aliases under /tmp); strict keeps the tmp home
            home = Path("/sc-home") if allow_net else tmp_root / "home"
            if not allow_net:
                home.mkdir()
            # M1: fail closed unless the fence canary certifies against THIS work
            # dir, THIS home, THIS network posture AND THESE runtime binds — and
            # the certificate is live and matches the fence we are about to run (R11).
            cert, report = _fence.certify(work_dir=work, original=target, home=home,
                                          allow_network=allow_net, runtime_binds=runtime_binds,
                                          writable_binds=writable_binds)
            cov["fence"] = {k: report.get(k) for k in ("bwrap", "breaches", "controls_missing",
                                                       "canary_done", "network")}
            why = _fence.verify_certificate(cert, work_dir=work, home=home,
                                            allow_network=allow_net, runtime_binds=runtime_binds,
                                            writable_binds=writable_binds)
            if why is not None:
                return self._fail(f"fence_unverified: {report.get('refused') or why}", cov)
            posture["cert_hash"] = cert.config_hash
            env = _fence.allowlisted_env(home=str(home))
            if allow_net:
                # PATH must point at the NEUTRAL runtime bins; the host PATH
                # (~/.local/bin, ~/.nvm) does not exist inside the namespace.
                env["PATH"] = ":".join((*plan.path_dirs, "/usr/bin", "/bin"))
                env.update(extra_env)
            cmd = self._cmd()
            fcmd = _fence.bwrap_argv(work_dir=work, home=home, allow_network=allow_net,
                                     runtime_binds=runtime_binds,
                                     writable_binds=writable_binds) + ["--", *cmd]
            import subprocess as _sp
            r = proc.run_command(fcmd, timeout=self.timeout, cwd=str(work), env=env,
                                 success_exit_codes=tuple(range(0, 256)),
                                 stdin=_sp.DEVNULL)   # codex exec blocks reading stdin otherwise
            # B1-residual (minimize on-disk credential exposure): a COPIED vendor
            # credential is only needed while the vendor process authenticates.
            # Scrub it the instant that process returns — before patch extraction/
            # validation — so it is not resident during the rest of the run and a
            # later uncatchable SIGKILL can strand at most a credential-free dir.
            if auth_kind == "oauth-file-copy":
                (tmp_root / "vendor-home" / _VENDOR_HOME[self.command][2]).unlink(missing_ok=True)
            diff = _patches.extract_patch(pristine, work, ceiling=tmp_root)
            if not diff.strip():
                return self._fail("no_patch: the fix produced no change", cov, ok_degrade=True)
            secret_family = bool(set(_norm_cwes(self.finding)) & _patches.SECRET_CWES)
            loc = (self.finding.get("locations") or [{}])[0]
            report_p = _patches.validate_patch(
                diff, target_files={loc.get("uri")} if loc.get("uri") else None,
                secret_family=secret_family)
            if not report_p.ok:
                return self._fail(f"patch_refused: {report_p.refused}", cov)
            patch_path = raw_dir / "fix.patch"
            patch_path.write_text(report_p.diff)
            rel = f"raw/{self.name.replace(':', '_')}/fix.patch"
            excluded = report_p.secret_in_patch
            art = Artifact(
                id=artifact_id(kind="fix", producer=self.name, path=rel, run_id=run_id),
                kind="fix", title=f"Patch for {loc.get('uri','?')}", path=rel,
                producer=self.name, family=self.family, dual_use=False,
                export_excluded=excluded, created_at=collected_at, model_id=self.model,
                entitlement=tier.name if tier else None, safeguard_posture=safeguard,
                format="patch", related_finding_ids=[self.finding.get("id")] if self.finding.get("id") else [])
            meta = {"sha256": report_p.sha256, "secret_in_patch": report_p.secret_in_patch,
                    "review_required": report_p.review_required, "files": report_p.files,
                    "base_commit": (report or {}).get("base_commit"), "exit_code": r.exit_code,
                    # the host-isolation posture rides with the patch so a
                    # reviewer sees the egress conditions the fix was made under
                    "posture": posture}
            cov.update({"patch": meta, "elapsed": r.elapsed_seconds})
            return ArmResult(name=self.name, kind=self.kind, family=self.family, ok=True,
                             exit_code=r.exit_code, error="", findings=[],
                             elapsed_seconds=r.elapsed_seconds, command=["<fenced>", self.command],
                             raw_path=str(patch_path), coverage=cov,
                             artifacts=[{**art.to_dict(), "patch": meta}])
        finally:
            _unregister_scratch(tmp_root)
            shutil.rmtree(tmp_root, ignore_errors=True)

    def _fail(self, error: str, cov: dict, *, ok_degrade: bool = False) -> ArmResult:
        return ArmResult(name=self.name, kind=self.kind, family=self.family, ok=ok_degrade,
                         exit_code=None, error=error, findings=[], coverage=cov,
                         command=["<fenced>", self.command])


def _norm_cwes(finding: dict) -> list[str]:
    tax = finding.get("taxonomy") or {}
    return [str(c).upper() for c in (tax.get("cwe") or [])]
