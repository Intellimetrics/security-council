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
    version_args: tuple[str, ...]
    network: bool                   # docker: allow network (rules/db)


SCANNER_SPECS: dict[str, ScannerSpec] = {
    "semgrep": ScannerSpec(
        name="semgrep", family="semgrep", bin="semgrep", image="semgrep/semgrep",
        local_args=("scan", "--config=p/default", "--sarif", "--output={out}/semgrep.sarif",
                    "--metrics=off", "{target}"),
        docker_args=("semgrep", "scan", "--config=p/default", "--sarif",
                     "--output=/out/semgrep.sarif", "--metrics=off", _MOUNT),
        sarif_name="semgrep.sarif", success_exit_codes=(0, 1),
        version_args=("--version",), network=True),
    "gitleaks": ScannerSpec(
        name="gitleaks", family="gitleaks", bin="gitleaks", image="zricethezav/gitleaks:latest",
        local_args=("detect", "--source={target}", "--no-git", "--report-format=sarif",
                    "--report-path={out}/gitleaks.sarif", "--redact"),
        docker_args=("detect", "--source=" + _MOUNT, "--no-git", "--report-format=sarif",
                     "--report-path=/out/gitleaks.sarif", "--redact"),
        sarif_name="gitleaks.sarif", success_exit_codes=(0, 1),
        version_args=("version",), network=False),
    "osv-scanner": ScannerSpec(
        name="osv-scanner", family="osv", bin="osv-scanner", image="ghcr.io/google/osv-scanner:latest",
        local_args=("scan", "source", "--format=sarif", "--output={out}/osv.sarif", "{target}"),
        docker_args=("scan", "source", "--format=sarif", "--output=/out/osv.sarif", _MOUNT),
        sarif_name="osv.sarif", success_exit_codes=(0, 1),
        version_args=("--version",), network=True),
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
                r = proc.run_command(["docker", "run", "--rm", self.spec.image, *self.spec.version_args],
                                     timeout=60)
            else:
                r = proc.run_command([self.spec.bin, *self.spec.version_args], timeout=30)
            return (r.stdout or r.stderr).strip().splitlines()[0] if (r.stdout or r.stderr) else None
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

        r = proc.run_command(cmd, timeout=1800, success_exit_codes=self.spec.success_exit_codes)
        version = self._version(use_docker)
        sarif_path = raw_dir / self.spec.sarif_name
        findings = []
        error = "" if r.ok else (r.stderr or f"exit {r.exit_code}")[:500]
        raw_count = 0
        if sarif_path.is_file():
            try:
                sarif = json.load(open(sarif_path))
                ctx = ParseContext(repo_root=target, scan_root=scan_root, source_id=self.name,
                                   source_kind="scanner", family=self.family, run_id=run_id,
                                   collected_at=collected_at, tool_version=version)
                findings = registry.normalize_sarif(sarif, self.name, ctx)
                raw_count = sum(len(run.get("results", [])) for run in sarif.get("runs", []))
                if not r.ok and findings:      # findings present => productive run, not a failure
                    r.ok = True
                    error = ""
            except Exception as e:  # noqa: BLE001
                error = error or f"sarif parse failed: {e}"
        return ArmResult(
            name=self.name, kind=self.kind, family=self.family, ok=r.ok, exit_code=r.exit_code,
            error=error, findings=findings, tool_version=version, elapsed_seconds=r.elapsed_seconds,
            command=cmd, raw_path=str(sarif_path) if sarif_path.is_file() else None,
            coverage={"raw_results": raw_count, "normalized": len(findings)},
        )
