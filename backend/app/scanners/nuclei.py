"""Nuclei DAST scanner adapter.

Executes ProjectDiscovery Nuclei against target URLs using non-destructive
template sets with JSON/JSONL output parsing and normalization.
"""

from __future__ import annotations

import json
import logging
import re
import shutil
from pathlib import Path

from app.core.config import get_settings
from app.models.enums import EvidenceLevel, Severity
from app.scanners.base import (
    NormalizedFinding,
    ScannerAdapter,
    compute_fingerprint,
    compute_normalized_fingerprint,
)
from app.security.dast_validator import validate_dast_url
from app.security.runner import RunnerConfig, RunResult, run_command

logger = logging.getLogger(__name__)

SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "unknown": Severity.UNKNOWN,
}


def _extract_cve(item: dict, template_id: str, title: str) -> str | None:
    """Extract CVE identifier from Nuclei classification, template id, or title."""
    classification = item.get("info", {}).get("classification", {})
    cve_id = classification.get("cve-id")
    if isinstance(cve_id, list) and cve_id:
        return str(cve_id[0]).upper()
    if isinstance(cve_id, str) and cve_id.strip():
        return cve_id.strip().upper()

    # Search in template id and title
    combined = f"{template_id} {title}"
    match = re.search(r"(CVE-\d{4}-\d{4,8})", combined, re.IGNORECASE)
    if match:
        return match.group(1).upper()
    return None


def _extract_cwe(item: dict) -> str | None:
    """Extract CWE identifier from Nuclei classification."""
    classification = item.get("info", {}).get("classification", {})
    cwe_id = classification.get("cwe-id")
    raw_cwe: str | None = None
    if isinstance(cwe_id, list) and cwe_id:
        raw_cwe = str(cwe_id[0])
    elif isinstance(cwe_id, str) and cwe_id.strip():
        raw_cwe = cwe_id.strip()

    if not raw_cwe:
        return None

    match = re.search(r"cwe[/-]?(\d+)", raw_cwe, re.IGNORECASE)
    if match:
        return f"CWE-{int(match.group(1))}"
    return raw_cwe.upper()


class NucleiScanner(ScannerAdapter):
    """Nuclei runtime vulnerability scanner integration."""

    @property
    def name(self) -> str:
        return "nuclei"

    async def is_available(self) -> bool:
        settings = get_settings()
        nuclei_bin = settings.nuclei_path
        if not shutil.which(nuclei_bin) and not Path(nuclei_bin).exists():
            return False
        try:
            result = await run_command(
                [nuclei_bin, "-version"],
                config=RunnerConfig(timeout=10, max_output_bytes=4096, allowed_roots=[]),
            )
            return result.return_code == 0
        except Exception:
            return False

    def detect_applicability(self, project_path: Path, target_url: str | None = None) -> bool:
        """Nuclei is applicable only when a valid runtime target_url is provided."""
        return bool(target_url and target_url.strip())

    def build_command(self, project_path: Path, target_url: str | None = None) -> list[str]:
        settings = get_settings()
        nuclei_bin = settings.nuclei_path
        url = target_url or ""
        # Non-destructive template sets, JSONL output, no interactsh, no color, disable auto-update
        return [
            nuclei_bin,
            "-u",
            url,
            "-jsonl",
            "-silent",
            "-nc",
            "-duc",
            "-no-interactsh",
            "-tags",
            "cve,misconfig,tech,exposure",
            "-severity",
            "info,low,medium,high,critical",
            "-timeout",
            "10",
        ]

    async def execute(
        self,
        project_path: Path,
        target_url: str | None = None,
        config: RunnerConfig | None = None,
    ) -> RunResult:
        if not target_url:
            return RunResult(
                return_code=-1,
                stdout="",
                stderr="Nuclei execution skipped: target_url is required",
            )

        settings = get_settings()
        validated_url = validate_dast_url(
            target_url,
            allowed_hosts=settings.get_dast_allowed_hosts(),
            enforce_allowlist=settings.dast_enforce_host_allowlist,
        )

        argv = self.build_command(project_path, target_url=validated_url)
        return await run_command(argv, cwd=project_path, config=config)

    def parse_result(self, result: RunResult) -> list[dict]:
        """Parse Nuclei JSON / JSONL output into a list of finding dicts."""
        if not result.stdout.strip():
            return []

        raw_findings: list[dict] = []
        for line in result.stdout.splitlines():
            line_str = line.strip()
            if not line_str:
                continue
            try:
                parsed = json.loads(line_str)
                if isinstance(parsed, dict):
                    raw_findings.append(parsed)
                elif isinstance(parsed, list):
                    raw_findings.extend(parsed)
            except json.JSONDecodeError:
                # Try parsing as a whole JSON document if line-by-line fails
                pass

        if not raw_findings and result.stdout.strip().startswith(("{", "[")):
            try:
                parsed = json.loads(result.stdout)
                if isinstance(parsed, list):
                    raw_findings.extend(parsed)
                elif isinstance(parsed, dict):
                    raw_findings.append(parsed)
            except json.JSONDecodeError:
                logger.warning("Failed to parse Nuclei JSON output")

        return raw_findings

    def normalize_findings(self, raw_findings: list[dict]) -> list[NormalizedFinding]:
        """Convert raw Nuclei JSON items into NormalizedFinding instances."""
        findings: list[NormalizedFinding] = []

        for item in raw_findings:
            if not isinstance(item, dict):
                continue

            info = item.get("info", {}) if isinstance(item.get("info"), dict) else {}
            template_id = (
                item.get("template-id")
                or item.get("templateID")
                or item.get("template")
                or "nuclei-template"
            )
            name = info.get("name") or template_id
            description = info.get("description") or ""

            sev_raw = str(info.get("severity", "info")).lower()
            severity = SEVERITY_MAP.get(sev_raw, Severity.UNKNOWN)

            matched_url = item.get("matched-at") or item.get("host") or item.get("url")
            cve = _extract_cve(item, template_id, name)
            cwe = _extract_cwe(item)

            remediation = info.get("remediation")
            reference = info.get("reference")
            primary_url = (
                reference[0]
                if isinstance(reference, list) and reference
                else (reference if isinstance(reference, str) else matched_url)
            )

            raw_fp = compute_fingerprint(
                scanner=self.name,
                cve=cve,
                cwe=cwe,
                url=matched_url,
                title=template_id,
            )
            norm_fp = compute_normalized_fingerprint(
                cve=cve,
                cwe=cwe,
                url=matched_url,
                title=template_id,
            )

            # Confidence: high for exact templates / CVEs
            confidence = 0.85 if cve else 0.75

            raw_dict = {
                "template_id": template_id,
                "name": name,
                "severity": sev_raw,
                "matched_at": matched_url,
                "cve": cve,
                "cwe": cwe,
                "remediation": remediation,
                "reference": reference,
                "extracted_results": item.get("extracted-results"),
                "curl_command": item.get("curl-command"),
            }

            findings.append(
                NormalizedFinding(
                    title=name,
                    description=description,
                    severity=severity,
                    confidence=confidence,
                    scanner_name=self.name,
                    cve=cve,
                    cwe=cwe,
                    url=matched_url or primary_url,
                    evidence_level=EvidenceLevel.RUNTIME_VALIDATED,
                    raw_data=raw_dict,
                    raw_fingerprint=raw_fp,
                    normalized_fingerprint=norm_fp,
                    evidences=[raw_dict],
                )
            )

        return findings
