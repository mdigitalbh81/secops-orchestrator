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
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.INFO,
}


class SemgrepScanner(ScannerAdapter):
    @property
    def name(self) -> str:
        return "semgrep"

    async def is_available(self) -> bool:
        result = await run_command(
            ["semgrep", "--version"],
            config=RunnerConfig(timeout=10, max_output_bytes=4096, allowed_roots=[]),
        )
        return result.return_code == 0

    def detect_applicability(self, project_path: Path) -> bool:
        # Semgrep can scan any code
        return True

    def build_command(self, project_path: Path) -> list[str]:
        return [
            "semgrep",
            "scan",
            "--json",
            "--config",
            "auto",
            str(project_path),
        ]

    def parse_result(self, result: RunResult) -> list[dict]:
        if not result.stdout.strip():
            return []
        try:
            data = json.loads(result.stdout)
            return data.get("results", [])
        except json.JSONDecodeError:
            logger.warning("Failed to parse semgrep JSON output")
            return []

    def normalize_findings(self, raw_findings: list[dict]) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        for item in raw_findings:
            check_id = item.get("check_id", "unknown")
            message = item.get("extra", {}).get("message", "")
            sev_str = item.get("extra", {}).get("severity", "INFO")
            severity = SEVERITY_MAP.get(sev_str, Severity.UNKNOWN)

            file_path = item.get("path", "")
            line_start = item.get("start", {}).get("line")
            line_end = item.get("end", {}).get("line")

            cwe_list = item.get("extra", {}).get("metadata", {}).get("cwe", [])
            cwe = cwe_list[0] if isinstance(cwe_list, list) and cwe_list else None
            if isinstance(cwe, str) and ": " in cwe:
                cwe = cwe.split(":")[0].strip()

            raw_fp = compute_fingerprint(
                scanner=self.name,
                cwe=cwe,
                file_path=file_path,
                line_start=line_start,
                title=check_id,
            )
            norm_fp = compute_normalized_fingerprint(
                cwe=cwe,
                file_path=file_path,
                title=check_id,
            )

            findings.append(
                NormalizedFinding(
                    title=check_id,
                    description=message,
                    severity=severity,
                    confidence=0.5,
                    scanner_name=self.name,
                    cwe=cwe,
                    file_path=file_path,
                    line_start=line_start,
                    line_end=line_end,
                    url=item.get("extra", {}).get("metadata", {}).get("source"),
                    raw_data=item,
                    raw_fingerprint=raw_fp,
                    normalized_fingerprint=norm_fp,
                )
            )
        return findings
