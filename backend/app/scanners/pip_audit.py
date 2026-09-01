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


class PipAuditScanner(ScannerAdapter):
    @property
    def name(self) -> str:
        return "pip-audit"

    async def is_available(self) -> bool:
        result = await run_command(
            ["pip-audit", "--version"],
            config=RunnerConfig(timeout=10, max_output_bytes=4096, allowed_roots=[]),
        )
        return result.return_code == 0

    def detect_applicability(self, project_path: Path) -> bool:
        """True if any pip-audit scan target is discovered in project tree."""
        from app.services.target_discovery import discover_scan_targets

        return any(
            t.scanner_name == self.name
            for t in discover_scan_targets(project_path)
        )

    def build_command(self, project_path: Path) -> list[str]:
        if (project_path / "requirements.txt").exists():
            return [
                "pip-audit",
                "--format",
                "json",
                "--requirement",
                str(project_path / "requirements.txt"),
            ]
        return ["pip-audit", "--format", "json"]

    def parse_result(self, result: RunResult) -> list[dict]:
        if not result.stdout.strip():
            return []
        try:
            data = json.loads(result.stdout)
            if isinstance(data, dict):
                return data.get("dependencies", [])
            if isinstance(data, list):
                return data
            return []
        except json.JSONDecodeError:
            logger.warning("Failed to parse pip-audit JSON output")
            return []

    def normalize_findings(self, raw_findings: list[dict]) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        for dep in raw_findings:
            pkg_name = dep.get("name", "unknown")
            installed = dep.get("version", "")
            vulns = dep.get("vulns", [])
            for vuln in vulns:
                vuln_id = vuln.get("id", "")
                fix_ver = vuln.get("fix_versions", [])
                fix_version = fix_ver[0] if fix_ver else None
                description = vuln.get("description", "")

                cve = vuln_id if vuln_id.startswith("CVE-") else None
                severity = Severity.UNKNOWN
                title = f"{vuln_id}: {pkg_name}"

                raw_fp = compute_fingerprint(
                    scanner=self.name, cve=cve, package_name=pkg_name, title=title
                )
                norm_fp = compute_normalized_fingerprint(
                    cve=cve, package_name=pkg_name, title=title
                )

                findings.append(
                    NormalizedFinding(
                        title=title,
                        description=description,
                        severity=severity,
                        confidence=0.7 if cve else 0.5,
                        scanner_name=self.name,
                        cve=cve,
                        package_name=pkg_name,
                        installed_version=installed,
                        fixed_version=fix_version,
                        raw_data=dep,
                        raw_fingerprint=raw_fp,
                        normalized_fingerprint=norm_fp,
                    )
                )
        return findings
