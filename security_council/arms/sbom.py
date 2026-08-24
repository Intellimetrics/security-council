"""SBOM generation arm — syft → CycloneDX 1.6 JSON (`scan --sbom`).

Produces a real software bill of materials for the scanned tree and attaches
it as a run ARTIFACT (`raw/sbom/sbom.cdx.json`, indexed in the manifest) —
never findings: an inventory is a document, not a gate-able defect, so it
rides the M-V3 analysis-arm path (out of coverage/clustering/the exit gate;
failure degrades informationally).

Tooling: syft (Anchore), local binary preferred, else the docker image —
cdxgen is the sanctioned alternative; **Trivy stays banned** (supply-chain
compromise Mar 2026, GHSA-69fq-xp46-6x23). The scan itself needs no network
(catalogers are local), so docker runs with ``--network=none`` and the
update check disabled — only the one-time image pull touches the network.

The CycloneDX VDR exporter (`report --format cyclonedx`) upgrades itself when
this artifact exists in a run: instead of a bare vulnerabilities-only VDR it
merges our findings INTO the syft SBOM (components preserved, affects refs
resolved against real inventory purls) — one document, inventory + findings.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from .. import proc
from ..artifacts import Artifact, artifact_id
from .base import ArmResult

IMAGE = "anchore/syft:latest"
_MOUNT = "/src"
OUTPUT_FORMAT = "cyclonedx-json@1.6"


class SbomArm:
    kind = "artifact"
    name = "sbom"
    family = "syft"
    supports_diff = False

    def __init__(self, *, image: str = IMAGE, timeout: int = 900) -> None:
        self.image = image
        self.timeout = int(timeout)

    def available(self) -> tuple[bool, str]:
        local = shutil.which("syft")
        if local:
            return True, f"local: {local}"
        if shutil.which("docker"):
            return True, f"docker: {self.image}"
        return False, "needs syft on PATH or docker"

    def _cmd(self, target: Path) -> list[str]:
        if shutil.which("syft"):
            return ["syft", "scan", f"dir:{target}", "-o", OUTPUT_FORMAT, "--quiet"]
        return ["docker", "run", "--rm", "--network=none",
                "-e", "SYFT_CHECK_FOR_APP_UPDATE=false",
                "-v", f"{target}:{_MOUNT}:ro", self.image,
                "scan", f"dir:{_MOUNT}", "-o", OUTPUT_FORMAT, "--quiet"]

    def run(self, target: Path, out_dir: Path, *, run_id: str,
            collected_at: str) -> ArmResult:
        target = Path(target).resolve()
        raw_dir = Path(out_dir) / "raw" / "sbom"
        raw_dir.mkdir(parents=True, exist_ok=True)
        cmd = self._cmd(target)
        r = proc.run_command(cmd, timeout=self.timeout)
        cov: dict = {"output_format": OUTPUT_FORMAT}

        def fail(msg: str) -> ArmResult:
            (raw_dir / "stderr.log").write_text(r.stderr or "")
            return ArmResult(name=self.name, kind=self.kind, family=self.family,
                             ok=False, exit_code=r.exit_code, error=msg, findings=[],
                             elapsed_seconds=r.elapsed_seconds, command=cmd, coverage=cov)

        if r.timed_out:
            return fail(f"timed out after {self.timeout}s")
        if not r.ok:
            return fail(f"syft failed (exit {r.exit_code}): {(r.stderr or '')[-300:]}")
        try:
            doc = json.loads(r.stdout)
        except ValueError:
            return fail("syft produced non-JSON output")
        if doc.get("bomFormat") != "CycloneDX":
            return fail("syft output is not a CycloneDX document")
        cov["components"] = len(doc.get("components") or [])
        tool_version = next((c.get("version") for c in
                             ((doc.get("metadata") or {}).get("tools") or {}).get(
                                 "components", []) if c.get("name") == "syft"), None)
        (raw_dir / "sbom.cdx.json").write_text(json.dumps(doc, indent=1) + "\n")
        rel = "raw/sbom/sbom.cdx.json"
        art = Artifact(
            id=artifact_id(kind="sbom", producer=self.name, path=rel, run_id=run_id),
            kind="sbom", title="Software bill of materials (CycloneDX)", path=rel,
            producer=self.name, family=self.family, dual_use=False,
            export_excluded=False, created_at=collected_at, format="cyclonedx-json")
        return ArmResult(name=self.name, kind=self.kind, family=self.family, ok=True,
                         exit_code=r.exit_code, error="", findings=[],
                         tool_version=tool_version, elapsed_seconds=r.elapsed_seconds,
                         command=cmd, raw_path=str(raw_dir / "sbom.cdx.json"),
                         coverage=cov, artifacts=[art.to_dict()])
