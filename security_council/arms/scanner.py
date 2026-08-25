"""Deterministic scanner arms (semgrep / gitleaks / osv-scanner), local or docker."""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from pathlib import Path

from .. import proc
from ..normalize import registry
from ..normalize.base import ParseContext
from .base import ArmResult

_MOUNT = "/src"

# The one ruleset the semgrep arm runs. Calibration records pin it (R7): a
# fitted record only auto-applies when the run's ruleset matches the pin.
SEMGREP_RULESET = "p/default"


@dataclass(frozen=True)
class ScannerSpec:
    name: str
    family: str
    bin: str
    image: str
    local_args: tuple[str, ...]     # {target} {out}
    docker_args: tuple[str, ...]    # run inside container; {out} is /out
    sarif_name: str
    success_exit_codes: tuple[int, ...]
    version_args: tuple[str, ...]           # local: [bin, *version_args]
    docker_version_args: tuple[str, ...]    # docker: [run IMAGE, *docker_version_args]
    network: bool                   # docker: allow network (rules/db)
    # Output the tool emits when it had NOTHING IN SCOPE rather than when it
    # failed. osv-scanner exits non-zero and writes no SARIF on a repo with no
    # dependency manifests, which is not-applicable, not a failure — without
    # this every dependency-free repo scans "degraded" (exit 3) instead of clean.
    not_applicable_markers: tuple[str, ...] = ()
    # Files IN THE SCANNED REPO that tell this tool to skip things. They are
    # honoured (a repo may legitimately ignore vendored code) but they mean
    # coverage is REDUCED, and a reduced scan must never report as verified.
    ignore_files: tuple[str, ...] = ()


SCANNER_SPECS: dict[str, ScannerSpec] = {
    "semgrep": ScannerSpec(
        name="semgrep", family="semgrep", bin="semgrep", image="semgrep/semgrep",
        local_args=("scan", f"--config={SEMGREP_RULESET}", "--sarif",
                    "--output={out}/semgrep.sarif",
                    "--metrics=off", "--exclude=.llm-council", "--exclude=.security-council",
                    "{target}"),
        docker_args=("semgrep", "scan", f"--config={SEMGREP_RULESET}", "--sarif",
                     "--output=/out/semgrep.sarif", "--metrics=off",
                     "--exclude=.llm-council", "--exclude=.security-council", _MOUNT),
        sarif_name="semgrep.sarif", success_exit_codes=(0, 1),
        version_args=("--version",), docker_version_args=("semgrep", "--version"), network=True,
        ignore_files=(".semgrepignore",)),
    "gitleaks": ScannerSpec(
        name="gitleaks", family="gitleaks", bin="gitleaks", image="zricethezav/gitleaks:latest",
        local_args=("detect", "--source={target}", "--no-git", "--report-format=sarif",
                    "--report-path={out}/gitleaks.sarif", "--redact"),
        docker_args=("detect", "--source=" + _MOUNT, "--no-git", "--report-format=sarif",
                     "--report-path=/out/gitleaks.sarif", "--redact"),
        sarif_name="gitleaks.sarif", success_exit_codes=(0, 1),
        version_args=("version",), docker_version_args=("version",), network=False,
        ignore_files=(".gitleaksignore",)),
    "osv-scanner": ScannerSpec(
        name="osv-scanner", family="osv", bin="osv-scanner", image="ghcr.io/google/osv-scanner:latest",
        local_args=("scan", "source", "--format=sarif", "--output={out}/osv.sarif", "{target}"),
        docker_args=("scan", "source", "--format=sarif", "--output=/out/osv.sarif", _MOUNT),
        sarif_name="osv.sarif", success_exit_codes=(0, 1),
        version_args=("--version",), docker_version_args=("--version",), network=True,
        not_applicable_markers=("no package sources found",),
        ignore_files=("osv-scanner.toml",)),
}


class ScannerArm:
    kind = "scanner"

    def __init__(self, name: str) -> None:
        if name not in SCANNER_SPECS:
            raise ValueError(f"unknown scanner: {name}")
        self.name = name
        self.spec = SCANNER_SPECS[name]
        self.family = self.spec.family

    def available(self) -> tuple[bool, str]:
        if shutil.which(self.spec.bin):
            return True, f"local: {shutil.which(self.spec.bin)}"
        if shutil.which("docker"):
            return True, f"docker: {self.spec.image}"
        return False, "neither the binary nor docker is available"

    def _version(self, use_docker: bool) -> str | None:
        try:
            if use_docker:
                r = proc.run_command(["docker", "run", "--rm", self.spec.image,
                                      *self.spec.docker_version_args], timeout=90)
            else:
                r = proc.run_command([self.spec.bin, *self.spec.version_args], timeout=30)
            if not r.ok or not r.stdout.strip():
                return None
            return r.stdout.strip().splitlines()[0]
        except Exception:
            return None

    def run(self, target: Path, out_dir: Path, *, run_id: str, collected_at: str) -> ArmResult:
        target = Path(target).resolve()
        raw_dir = out_dir / "raw" / self.name
        raw_dir.mkdir(parents=True, exist_ok=True)
        use_docker = shutil.which(self.spec.bin) is None
        if use_docker:
            net = [] if self.spec.network else ["--network=none"]
            cmd = ["docker", "run", "--rm", *net,
                   "-v", f"{target}:{_MOUNT}:ro", "-v", f"{raw_dir}:/out",
                   self.spec.image, *self.spec.docker_args]
            scan_root: str | None = _MOUNT
        else:
            fmt = {"target": str(target), "out": str(raw_dir)}
            cmd = [self.spec.bin, *[a.format(**fmt) for a in self.spec.local_args]]
            scan_root = str(target)

        # R12 round 16: a repo's own ignore-files are copied into the scratch tree
        # and honoured, so `printf '*' > .semgrepignore` turned the vulnerable
        # fixture from 3 findings / exit 1 into a CLEAN, `verified`, exit-0 scan.
        # Two lines to write, no store and no panel involved, default profile.
        # They stay honoured — ignoring vendored code is legitimate — but a scan
        # the repo told to look away is not a verified scan.
        ignored = sorted({str(pth.relative_to(target))
                          for name in self.spec.ignore_files
                          for pth in target.rglob(name) if pth.is_file()})

        r = proc.run_command(cmd, timeout=1800, success_exit_codes=self.spec.success_exit_codes)
        version = self._version(use_docker)
        sarif_path = raw_dir / self.spec.sarif_name
        findings = []
        error = "" if r.ok else (r.stderr or f"exit {r.exit_code}")[:500]
        raw_count = 0
        cov: dict = {"ignore_files": ignored} if ignored else {}
        # R12 round 11: this was a substring match over stdout+stderr COMBINED,
        # so any failed run whose output happened to contain the marker — a
        # scanned path, a longer error quoting it — was laundered into VERIFIED
        # coverage and a clean gate. Match only whole stderr LINES that begin
        # with the marker, which is how the tool actually emits it
        # ("No package sources found, --help for usage information.").
        _lines = [ln.strip().lower() for ln in (r.stderr or "").splitlines()]
        not_applicable = any(ln.startswith(m) for ln in _lines
                             for m in self.spec.not_applicable_markers)
        if not sarif_path.is_file():
            if not_applicable and not r.timed_out:
                # nothing in scope for this tool — honest "clean" for its category.
                # Bounded to a run that actually finished: a timeout that happens
                # to print the marker is a failure, not a not-applicable.
                r.ok, error = True, ""
                cov["not_applicable"] = True
            elif r.ok:
                # R12: THE dangerous case. The tool exited inside
                # success_exit_codes (semgrep/gitleaks/osv all treat 1 as
                # success = "findings found") but produced NO report, so nothing
                # was actually examined — and we returned ok=True with
                # findings=[], i.e. a silent CLEAN result. That is the exact
                # failure mode this project exists to prevent. Fail loudly.
                r.ok = False
                error = (f"exited {r.exit_code} but wrote no {self.spec.sarif_name} — "
                         f"nothing was scanned (coverage unverified, NOT clean)")
                cov["coverage_unverified"] = True
        if sarif_path.is_file():
            try:
                sarif = json.load(open(sarif_path))
                ctx = ParseContext(repo_root=target, scan_root=scan_root, source_id=self.name,
                                   source_kind="scanner", family=self.family, run_id=run_id,
                                   collected_at=collected_at, tool_version=version)
                findings = registry.normalize_sarif(sarif, self.name, ctx)
                raw_count = sum(len(run.get("results", [])) for run in sarif.get("runs", []))
                # findings present => productive run, not a failure — EXCEPT a
                # timeout, whose report is whatever had been flushed when the
                # clock ran out. R12: resurrecting that hid a partial scan.
                if not r.ok and findings and not r.timed_out:
                    r.ok = True
                    error = ""
                elif r.timed_out and findings:
                    cov["partial_scan"] = True
            except Exception as e:  # noqa: BLE001
                # R12: this set an error string but left r.ok TRUE, so an
                # unreadable report produced ok=True with findings=[] — the same
                # silent clean result as a missing report, one branch over.
                r.ok = False
                error = error or f"sarif parse failed: {e}"
                cov["coverage_unverified"] = True
        return ArmResult(
            name=self.name, kind=self.kind, family=self.family, ok=r.ok, exit_code=r.exit_code,
            error=error, findings=findings, tool_version=version, elapsed_seconds=r.elapsed_seconds,
            command=cmd, raw_path=str(sarif_path) if sarif_path.is_file() else None,
            coverage={"raw_results": raw_count, "normalized": len(findings), **cov},
        )
