"""Core scan orchestration logic.

Coordinates scanner detection, execution, parsing, normalization,
deduplication, correlation, confidence adjustment, and risk gating.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.models.correlation import CorrelationGroup
from app.models.enums import ScannerRunStatus, ScanStatus
from app.models.finding import Finding, FindingEvidence
from app.models.scan import Scan
from app.models.scanner_run import ScannerRun
from app.scanners import get_all_scanners
from app.scanners.base import NormalizedFinding
from app.security.runner import RunnerConfig, validate_path
from app.services.confidence import adjust_confidence
from app.services.correlation import correlate_findings
from app.services.dedup import deduplicate_findings
from app.services.risk_engine import compute_risk_gate
from app.services.stack_detector import detect_applicable_scanners

logger = logging.getLogger(__name__)


async def run_scan(scan_id: str, session: AsyncSession) -> None:
    """Execute the full scan pipeline for a given scan record."""
    scan = await session.get(Scan, scan_id)
    if scan is None:
        logger.error("Scan %s not found", scan_id)
        return

    scan.status = ScanStatus.RUNNING
    await session.commit()

    settings = get_settings()

    try:
        project_path = validate_path(Path(scan.source_path), [settings.allowed_workspace_root])
    except Exception as exc:
        scan.status = ScanStatus.FAILED
        scan.error_message = f"Invalid source path: {exc}"
        scan.completed_at = datetime.now(UTC)
        await session.commit()
        return

    if not project_path.is_dir():
        scan.status = ScanStatus.FAILED
        scan.error_message = f"Source path does not exist: {scan.source_path}"
        scan.completed_at = datetime.now(UTC)
        await session.commit()
        return

    scanners = get_all_scanners()
    detection = await detect_applicable_scanners(project_path, scanners)

    all_findings: list[NormalizedFinding] = []

    for scanner_name, info in detection.items():
        scanner = info["scanner"]
        applicable = info["applicable"]
        available = info["available"]

        runner = ScannerRun(
            scan_id=scan_id,
            scanner_name=scanner_name,
        )

        if not applicable:
            runner.status = ScannerRunStatus.NOT_APPLICABLE
            session.add(runner)
            continue

        if not available:
            runner.status = ScannerRunStatus.UNAVAILABLE
            if scanner_name == "ai-appsec":
                runner.error_message = "AI AppSec Reviewer is disabled or not configured"
            else:
                runner.error_message = f"{scanner_name} not installed"
            session.add(runner)
            continue

        runner.status = ScannerRunStatus.RUNNING
        session.add(runner)
        await session.commit()

        start_time = datetime.now(UTC)
        try:
            config = RunnerConfig(
                timeout=settings.scanner_timeout,
                max_output_bytes=settings.scanner_max_output_bytes,
                allowed_roots=[settings.allowed_workspace_root, project_path],
            )
            result = await scanner.execute(project_path, config=config)
            runner.raw_output = result.stdout[:100000] if result.stdout else None
            if result.timed_out:
                runner.status = ScannerRunStatus.FAILED
                runner.error_message = "Scanner timed out"
                runner.completed_at = datetime.now(UTC)
                runner.duration_seconds = (runner.completed_at - start_time).total_seconds()
                continue

            raw_findings = scanner.parse_result(result)
            normalized = scanner.normalize_findings(raw_findings)
            all_findings.extend(normalized)
            runner.status = ScannerRunStatus.COMPLETED
            runner.completed_at = datetime.now(UTC)
            runner.duration_seconds = (runner.completed_at - start_time).total_seconds()
        except Exception as exc:
            logger.exception("Scanner %s failed", scanner_name)
            runner.status = ScannerRunStatus.FAILED
            runner.error_message = str(exc)[:1000]
            runner.completed_at = datetime.now(UTC)
            runner.duration_seconds = (runner.completed_at - start_time).total_seconds()

    # 1. Deterministic deduplication
    deduped = deduplicate_findings(all_findings)

    # 2. Intelligent cross-scanner correlation
    correlation_groups = correlate_findings(deduped, scan_id)

    # 3. Confidence scoring v2
    deduped = adjust_confidence(deduped)

    # 4. Risk gate evaluation
    risk_gate = compute_risk_gate(deduped)

    # 5. Persist correlation groups and findings
    for group_data in correlation_groups:
        db_group = CorrelationGroup(
            id=group_data.id,
            scan_id=scan_id,
            canonical_title=group_data.canonical_title,
            canonical_cwe=group_data.canonical_cwe,
            canonical_cve=group_data.canonical_cve,
            severity=group_data.severity,
            confidence=group_data.confidence,
            evidence_level=group_data.evidence_level,
            status=group_data.status,
            remediation_recommendation=group_data.remediation_recommendation,
        )
        session.add(db_group)
        await session.flush()

        for nf in group_data.findings:
            finding = Finding(
                scan_id=scan_id,
                scanner_name=nf.scanner_name,
                title=nf.title,
                description=nf.description,
                severity=nf.severity,
                confidence=nf.confidence,
                evidence_level=nf.evidence_level,
                correlation_group_id=db_group.id,
                cwe=nf.cwe,
                cve=nf.cve,
                file_path=nf.file_path,
                line_start=nf.line_start,
                line_end=nf.line_end,
                package_name=nf.package_name,
                installed_version=nf.installed_version,
                fixed_version=nf.fixed_version,
                url=nf.url,
                raw_fingerprint=nf.raw_fingerprint,
                normalized_fingerprint=nf.normalized_fingerprint,
            )
            session.add(finding)
            await session.flush()

            if nf.raw_data:
                evidence = FindingEvidence(
                    finding_id=finding.id,
                    scanner_name=nf.scanner_name,
                    raw_data=nf.raw_data,
                )
                session.add(evidence)

    scan.status = ScanStatus.COMPLETED
    scan.risk_gate = risk_gate
    scan.completed_at = datetime.now(UTC)
    await session.commit()
    logger.info(
        "Scan %s completed: %d findings in %d correlation groups, risk_gate=%s",
        scan_id,
        len(deduped),
        len(correlation_groups),
        risk_gate.value,
    )
