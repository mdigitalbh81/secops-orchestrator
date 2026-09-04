"""OWASP ZAP DAST scanner adapter.

Integrates OWASP ZAP non-destructive baseline/passive scan mode
against validated target URLs via CLI or daemon REST API.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import shutil
from pathlib import Path

import httpx

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

RISK_MAP: dict[str, Severity] = {
    "3": Severity.HIGH,
    "high": Severity.HIGH,
    "2": Severity.MEDIUM,
    "medium": Severity.MEDIUM,
    "1": Severity.LOW,
    "low": Severity.LOW,
    "0": Severity.INFO,
    "informational": Severity.INFO,
    "info": Severity.INFO,
}

CONFIDENCE_MAP: dict[str, float] = {
    "3": 0.85,
    "high": 0.85,
    "2": 0.70,
    "medium": 0.70,
    "1": 0.50,
    "low": 0.50,
    "0": 0.20,
    "falsepositive": 0.20,
}


class ZapScanner(ScannerAdapter):
    """OWASP ZAP passive/baseline scanner integration."""

    @property
    def name(self) -> str:
        return "zap"

    async def is_available(self) -> bool:
        settings = get_settings()
        zap_bin = settings.zap_path
        if shutil.which(zap_bin) or Path(zap_bin).exists():
            try:
                result = await run_command(
                    [zap_bin, "-h"],
                    config=RunnerConfig(timeout=10, max_output_bytes=4096, allowed_roots=[]),
                )
                if result.return_code in (0, 1, 2):
                    return True
            except Exception:  # noqa: S110
                logger.debug("ZAP binary check failed for %s", zap_bin)

        if settings.zap_url:
            try:
                async with httpx.AsyncClient(timeout=5.0) as client:
                    resp = await client.get(f"{settings.zap_url.rstrip('/')}/JSON/core/view/version/")
                    if resp.status_code == 200 and "version" in resp.json():
                        return True
            except Exception:  # noqa: S110
                logger.debug("ZAP REST API check failed for %s", settings.zap_url)

        return False

    def detect_applicability(self, project_path: Path, target_url: str | None = None) -> bool:
        """ZAP is applicable only when a valid runtime target_url is provided."""
        return bool(target_url and target_url.strip())

    def build_command(self, project_path: Path, target_url: str | None = None) -> list[str]:
        settings = get_settings()
        zap_bin = settings.zap_path
        url = target_url or ""
        report_file = project_path / "zap_report.json"
        return [
            zap_bin,
            "-t",
            url,
            "-J",
            str(report_file),
            "-m",
            "5",
            "-I",
        ]

    async def execute(
        self,
        project_path: Path,
        target_url: str | None = None,
        config: RunnerConfig | None = None,
    ) -> RunResult:
        """Execute ZAP and capture report JSON via CLI or daemon REST API."""
        if not target_url:
            return RunResult(
                return_code=-1,
                stdout="",
                stderr="ZAP execution skipped: target_url is required",
            )

        settings = get_settings()
        validated_url = validate_dast_url(
            target_url,
            allowed_hosts=settings.get_dast_allowed_hosts(),
            enforce_allowlist=settings.dast_enforce_host_allowlist,
        )

        zap_bin = settings.zap_path
        if shutil.which(zap_bin) or Path(zap_bin).exists():
            argv = self.build_command(project_path, target_url=validated_url)
            result = await run_command(argv, cwd=project_path, config=config)
            report_file = project_path / "zap_report.json"
            if report_file.exists():
                try:
                    report_content = report_file.read_text(encoding="utf-8")
                    if not result.stdout.strip().startswith("{"):
                        result.stdout = report_content
                except Exception as exc:
                    logger.warning("Failed to read ZAP report file %s: %s", report_file, exc)
            return result

        if settings.zap_url:
            zap_base = settings.zap_url.rstrip("/")
            timeout_sec = config.timeout if config else 120
            try:
                async with httpx.AsyncClient(timeout=timeout_sec) as client:
                    with contextlib.suppress(Exception):
                        await client.get(
                            f"{zap_base}/JSON/core/action/accessUrl/",
                            params={"url": validated_url},
                        )
                    spider_res = await client.get(
                        f"{zap_base}/JSON/spider/action/scan/",
                        params={"url": validated_url, "maxChildren": "10", "recurse": "true", "subtreeOnly": "true"},
                    )
                    spider_data = spider_res.json()
                    scan_id = spider_data.get("scan", "0")

                    for _ in range(30):
                        status_res = await client.get(
                            f"{zap_base}/JSON/spider/view/status/",
                            params={"scanId": scan_id},
                        )
                        if status_res.json().get("status") == "100":
                            break
                        await asyncio.sleep(1)

                    for _ in range(15):
                        pscan_res = await client.get(f"{zap_base}/JSON/pscan/view/recordsToScan/")
                        records = int(pscan_res.json().get("recordsToScan", "0"))
                        if records <= 0:
                            break
                        await asyncio.sleep(1)

                    alerts_res = await client.get(
                        f"{zap_base}/JSON/core/view/alerts/",
                        params={"baseurl": validated_url},
                    )
                    alerts = alerts_res.json().get("alerts", [])
                    if not alerts:
                        all_alerts_res = await client.get(f"{zap_base}/JSON/core/view/alerts/")
                        alerts = all_alerts_res.json().get("alerts", [])

                    report_json = json.dumps({"alerts": alerts})
                    with contextlib.suppress(Exception):
                        (project_path / "zap_report.json").write_text(report_json, encoding="utf-8")

                    return RunResult(return_code=0, stdout=report_json, stderr="")
            except httpx.TimeoutException:
                return RunResult(return_code=-1, stdout="", stderr="ZAP API request timed out", timed_out=True)
            except Exception as exc:
                return RunResult(return_code=1, stdout="", stderr=f"ZAP API execution error: {exc}")

        return RunResult(return_code=-1, stdout="", stderr="ZAP neither available via CLI nor REST API")

    def parse_result(self, result: RunResult) -> list[dict]:
        """Parse ZAP JSON report format into a list of alert dicts."""
        if not result.stdout.strip():
            return []
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            logger.warning("Failed to parse ZAP JSON output")
            return []

        raw_alerts: list[dict] = []
        if isinstance(data, dict) and "site" in data:
            sites = data.get("site", [])
            if isinstance(sites, list):
                for s in sites:
                    if isinstance(s, dict):
                        raw_alerts.extend(s.get("alerts", []))
            elif isinstance(sites, dict):
                raw_alerts.extend(sites.get("alerts", []))
        elif isinstance(data, dict) and "alerts" in data:
            raw_alerts.extend(data.get("alerts", []))
        elif isinstance(data, list):
            raw_alerts.extend(data)

        return raw_alerts

    def normalize_findings(self, raw_findings: list[dict]) -> list[NormalizedFinding]:
        """Convert raw ZAP alerts to NormalizedFinding instances."""
        findings: list[NormalizedFinding] = []
        for item in raw_findings:
            if not isinstance(item, dict):
                continue

            title = item.get("alert") or item.get("name") or "ZAP Alert"
            description = item.get("desc") or item.get("description") or ""
            risk_val = item.get("riskcode") or item.get("riskdesc") or item.get("risk") or ""
            risk_parts = str(risk_val).strip().lower().split()
            risk_raw = risk_parts[0] if risk_parts else ""
            severity = RISK_MAP.get(risk_raw, Severity.UNKNOWN)
            conf_val = item.get("confidence") or "2"
            conf_parts = str(conf_val).strip().lower().split()
            conf_raw = conf_parts[0] if conf_parts else "2"
            confidence = CONFIDENCE_MAP.get(conf_raw, 0.65)

            cwe_raw = item.get("cweid")
            cwe: str | None = None
            if cwe_raw is not None and str(cwe_raw).strip() and str(cwe_raw).strip() not in ("0", "-1", "None", ""):
                cwe_str = str(cwe_raw).strip()
                cwe = f"CWE-{cwe_str}" if not cwe_str.upper().startswith("CWE-") else cwe_str.upper()

            url: str | None = item.get("url")
            instances = item.get("instances", [])
            evidence_data: list[dict] = []
            if isinstance(instances, list) and instances:
                first_inst = instances[0]
                if isinstance(first_inst, dict) and not url:
                    url = first_inst.get("uri")
                evidence_data = instances
            elif isinstance(instances, dict):
                if not url:
                    url = instances.get("uri")
                evidence_data = [instances]

            remediation = item.get("solution") or item.get("otherinfo")
            reference = item.get("reference")

            raw_fp = compute_fingerprint(
                scanner=self.name,
                cwe=cwe,
                url=url,
                title=title,
            )
            norm_fp = compute_normalized_fingerprint(
                cwe=cwe,
                url=url,
                title=title,
            )

            raw_dict = {
                "alert": title,
                "risk": risk_raw,
                "cweid": cwe,
                "url": url,
                "instances": evidence_data,
                "solution": remediation,
                "reference": reference,
            }

            findings.append(
                NormalizedFinding(
                    title=title,
                    description=description,
                    severity=severity,
                    confidence=confidence,
                    scanner_name=self.name,
                    cwe=cwe,
                    url=url,
                    evidence_level=EvidenceLevel.RUNTIME_VALIDATED,
                    raw_data=raw_dict,
                    raw_fingerprint=raw_fp,
                    normalized_fingerprint=norm_fp,
                    evidences=evidence_data if evidence_data else [raw_dict],
                )
            )

        return findings
