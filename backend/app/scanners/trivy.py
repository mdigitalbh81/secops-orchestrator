from __future__ import annotations

import json
import logging
from pathlib import Path

from app.models.enums import Severity
from app.scanners.base import (
    NormalizedFinding,
    ScannerAdapter,
    compute_fingerprint,
    compute_normalized_fingerprint,
)
from app.security.runner import RunnerConfig, RunResult, run_command

logger = logging.getLogger(__name__)

SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "UNKNOWN": Severity.UNKNOWN,
}


class TrivyScanner(ScannerAdapter):
    @property
    def name(self) -> str:
        return "trivy"

    async def is_available(self) -> bool:
        result = await run_command(
            ["trivy", "--version"],
            config=RunnerConfig(timeout=10, max_output_bytes=4096, allowed_roots=[]),
        )
        return result.return_code == 0

    def detect_applicability(self, project_path: Path, target_url: str | None = None) -> bool:
        """Trivy fs scan applies to any valid project directory."""
        return project_path.is_dir()

    def build_command(self, project_path: Path, target_url: str | None = None) -> list[str]:
        return [
            "trivy",
            "fs",
            "--format",
            "json",
            "--no-progress",
            "--scanners",
            "vuln",
            str(project_path),
        ]

    def parse_result(self, result: RunResult) -> list[dict]:
        if result.return_code != 0 and not result.stdout.strip():
            raise RuntimeError(
                f"Trivy execution failed (code {result.return_code}): {result.stderr.strip()}"
            )
        if not result.stdout.strip():
            return []
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                f"Failed to parse trivy JSON output: {result.stderr.strip() or result.stdout[:200]}"
            ) from exc

        findings: list[dict] = []
        results = data.get("Results", [])
        for r in results:
            for vuln in r.get("Vulnerabilities", []):
                vuln["_target"] = r.get("Target", "")
                findings.append(vuln)
        return findings

    def normalize_findings(self, raw_findings: list[dict]) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        for vuln in raw_findings:
            vuln_id = vuln.get("VulnerabilityID", "")
            pkg_name = vuln.get("PkgName", "unknown")
            severity_str = vuln.get("Severity", "UNKNOWN")
            severity = SEVERITY_MAP.get(severity_str, Severity.UNKNOWN)
            title = vuln.get("Title", vuln_id)
            description = vuln.get("Description", "")

            cve = vuln_id if vuln_id.startswith("CVE-") else None
            installed = vuln.get("InstalledVersion", "")
            fixed = vuln.get("FixedVersion", "")
            url = vuln.get("PrimaryURL", "")

            cwes = vuln.get("CweIDs", [])
            cwe = cwes[0] if cwes else None

            raw_fp = compute_fingerprint(
                scanner=self.name, cve=cve, cwe=cwe, package_name=pkg_name, title=title
            )
            norm_fp = compute_normalized_fingerprint(
                cve=cve, cwe=cwe, package_name=pkg_name, title=title
            )

            findings.append(
                NormalizedFinding(
                    title=title,
                    description=description,
                    severity=severity,
                    confidence=0.7 if cve else 0.5,
                    scanner_name=self.name,
                    cve=cve,
                    cwe=cwe,
                    package_name=pkg_name,
                    installed_version=installed,
                    fixed_version=fixed or None,
                    url=url or None,
                    raw_data=vuln,
                    raw_fingerprint=raw_fp,
                    normalized_fingerprint=norm_fp,
                )
            )
        return findings
