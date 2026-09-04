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
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "moderate": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


class NpmAuditScanner(ScannerAdapter):
    @property
    def name(self) -> str:
        return "npm-audit"

    async def is_available(self) -> bool:
        result = await run_command(
            ["npm", "--version"],
            config=RunnerConfig(timeout=10, max_output_bytes=4096, allowed_roots=[]),
        )
        return result.return_code == 0

    def detect_applicability(self, project_path: Path, target_url: str | None = None) -> bool:
        """True if any npm-audit scan target is discovered in project tree."""
        from app.services.target_discovery import discover_scan_targets

        return any(t.scanner_name == self.name for t in discover_scan_targets(project_path))

    def build_command(self, project_path: Path, target_url: str | None = None) -> list[str]:
        return ["npm", "audit", "--json"]

    def parse_result(self, result: RunResult) -> list[dict]:
        if not result.stdout.strip():
            return []
        try:
            data = json.loads(result.stdout)
            vulns = data.get("vulnerabilities", {})
            return list(vulns.values())
        except json.JSONDecodeError:
            logger.warning("Failed to parse npm audit JSON output")
            return []

    def normalize_findings(self, raw_findings: list[dict]) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        for item in raw_findings:
            pkg_name = item.get("name", "unknown")
            severity_str = item.get("severity", "info")
            severity = SEVERITY_MAP.get(severity_str, Severity.UNKNOWN)
            title = item.get("title", f"Vulnerability in {pkg_name}")
            via = item.get("via", [])

            cve = None
            url = None
            description = ""
            if via and isinstance(via[0], dict):
                cve = via[0].get("cve")
                url = via[0].get("url")
                title = via[0].get("title", title)
                description = via[0].get("title", "")

            fixed_version = item.get("fixAvailable", {})
            fix_ver = None
            if isinstance(fixed_version, dict):
                fix_ver = fixed_version.get("version")

            installed = item.get("range", "")

            raw_fp = compute_fingerprint(
                scanner=self.name, cve=cve, package_name=pkg_name, title=title
            )
            norm_fp = compute_normalized_fingerprint(cve=cve, package_name=pkg_name, title=title)

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
                    fixed_version=fix_ver,
                    url=url,
                    raw_data=item,
                    raw_fingerprint=raw_fp,
                    normalized_fingerprint=norm_fp,
                )
            )
        return findings
