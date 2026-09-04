"""Core scan orchestration logic.

Coordinates scanner detection, execution, parsing, normalization,
deduplication, correlation, confidence adjustment, and risk gating.
Supports monorepos by discovering per-scanner targets via target_discovery
and executing each target independently within a single ScannerRun.
"""

from __future__ import annotations

import json
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
from app.scanners.base import NormalizedFinding, ScannerAdapter
from app.security.runner import RunnerConfig, redact_secrets, validate_path
from app.services.confidence import adjust_confidence
from app.services.correlation import correlate_findings
from app.services.dedup import deduplicate_findings
from app.services.risk_engine import compute_risk_gate
from app.services.stack_detector import detect_applicable_scanners
from app.services.target_discovery import ScanTarget, discover_scan_targets

logger = logging.getLogger(__name__)


def _normalize_file_path(
    file_path: str | None,
    target_path: Path,
    workspace_root: Path,
) -> str | None:
    """Normalize a finding's file_path relative to the workspace_root."""
    if not file_path:
        return file_path
    p = Path(file_path)
    # If relative, resolve against target's scan directory
    if not p.is_absolute():
        p = (target_path / p).resolve()
    # Make relative to workspace root
    try:
        return str(p.relative_to(workspace_root.resolve()))
    except ValueError:
        # Path is outside workspace; keep as-is
        return file_path


def _extract_target_provenance(
    target: ScanTarget,
    workspace_root: Path,
) -> tuple[str, str | None]:
    """Derive (subproject, manifest) strings from a ScanTarget."""
    if target.manifest_path:
        manifest_str = str(target.manifest_path)
        parent_str = str(target.manifest_path.parent)
        subproject_str = parent_str if parent_str != "." else "root"
    else:
        try:
            rel = target.path.resolve().relative_to(workspace_root.resolve())
            subproject_str = str(rel) if str(rel) != "." else "root"
        except ValueError:
            subproject_str = target.path.name or "root"
        manifest_str = None
    return subproject_str, manifest_str


async def _execute_scanner_for_target(
    scanner: ScannerAdapter,
    target: ScanTarget,
    workspace_root: Path,
    config: RunnerConfig,
    target_url: str | None = None,
) -> tuple[list[NormalizedFinding], str | None, bool, str, str, float]:
    """Execute a scanner against a single target.

    Returns (findings, error_message, timed_out, stdout, stderr, duration_seconds).
    """
    t0 = datetime.now(UTC)
    stdout = ""
    stderr = ""
    try:
        # Validate target path stays strictly within workspace root
        validate_path(target.path, [workspace_root])
        effective_target_url = target.metadata.get("target_url") or target_url
        result = await scanner.execute(
            target.path,
            target_url=effective_target_url,
            config=config,
        )
        duration = (datetime.now(UTC) - t0).total_seconds()
        stdout = redact_secrets(result.stdout or "")
        stderr = redact_secrets(result.stderr or "")

        if result.timed_out:
            return [], "Scanner timed out", True, stdout, stderr, duration

        if result.return_code != 0 and not stdout.strip() and result.stderr.strip():
            # Fatal tool execution error (e.g. crash / missing config)
            return [], stderr[:1000], False, stdout, stderr, duration

        raw_findings = scanner.parse_result(result)
        normalized = scanner.normalize_findings(raw_findings)

        subproject_str, manifest_str = _extract_target_provenance(target, workspace_root)

        # Normalize file paths relative to workspace root and inject subproject provenance
        for nf in normalized:
            if nf.file_path:
                nf.file_path = _normalize_file_path(nf.file_path, target.path, workspace_root)
            # Inject subproject provenance into raw_data to survive dedup & correlation
            if isinstance(nf.raw_data, dict):
                nf.raw_data["subproject"] = subproject_str
                if manifest_str:
                    nf.raw_data["manifest"] = manifest_str
            elif nf.raw_data is None:
                nf.raw_data = {
                    "subproject": subproject_str,
                    "manifest": manifest_str,
                }
            else:
                nf.raw_data = {
                    "raw": nf.raw_data,
                    "subproject": subproject_str,
                    "manifest": manifest_str,
                }

        return normalized, None, False, stdout, stderr, duration

    except Exception as exc:
        duration = (datetime.now(UTC) - t0).total_seconds()
        logger.exception("Scanner %s failed on target %s", scanner.name, target.path)
        return [], str(exc)[:1000], False, stdout, stderr, duration


async def run_scan(scan_id: str, session: AsyncSession) -> None:
    """Execute full scan pipeline for a given scan record."""
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
    detection = await detect_applicable_scanners(project_path, scanners, target_url=scan.target_url)

    # Discover monorepo & DAST targets
    targets = discover_scan_targets(project_path, target_url=scan.target_url)

    # Index targets by scanner name
    targets_by_scanner: dict[str, list[ScanTarget]] = {}
    for t in targets:
        targets_by_scanner.setdefault(t.scanner_name, []).append(t)

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
        scanner_targets = targets_by_scanner.get(scanner_name, [])

        # For scanners with no discovered subtargets: fall back to project root
        if not scanner_targets:
            scanner_targets = [
                ScanTarget(
                    path=project_path,
                    scanner_name=scanner_name,
                    target_type="repository",
                )
            ]

        config = RunnerConfig(
            timeout=settings.scanner_timeout,
            max_output_bytes=settings.scanner_max_output_bytes,
            allowed_roots=[settings.allowed_workspace_root, project_path],
        )

        subtarget_results: list[dict] = []
        scanner_findings: list[NormalizedFinding] = []
        last_error: str | None = None

        for target in scanner_targets:
            (
                findings,
                error,
                timed_out,
                stdout,
                stderr,
                duration,
            ) = await _execute_scanner_for_target(
                scanner,
                target,
                project_path,
                config,
                target_url=scan.target_url,
            )

            subproject_str, manifest_str = _extract_target_provenance(target, project_path)
            status_str = "TIMED_OUT" if timed_out else ("FAILED" if error else "COMPLETED")

            max_stream_snip = 20000
            stdout_snip = stdout[:max_stream_snip] if stdout else ""
            stderr_snip = stderr[:max_stream_snip] if stderr else ""

            subtarget_info = {
                "target_path": str(target.path),
                "target_type": target.target_type,
                "subproject": subproject_str,
                "manifest": manifest_str,
                "status": status_str,
                "findings_count": len(findings),
                "duration_seconds": round(duration, 3),
                "stdout": stdout_snip,
                "stderr": stderr_snip,
                "error": error,
            }
            subtarget_results.append(subtarget_info)

            if error:
                last_error = error
            else:
                scanner_findings.extend(findings)

        all_findings.extend(scanner_findings)

        # Store subtarget metadata in raw output for auditability
        raw_output_obj = {"subtargets": subtarget_results}
        runner.raw_output = json.dumps(raw_output_obj, default=str)[:100000]

        total_targets = len(subtarget_results)
        completed_targets = sum(1 for r in subtarget_results if r["status"] == "COMPLETED")
        failed_targets = sum(1 for r in subtarget_results if r["status"] in ("FAILED", "TIMED_OUT"))

        if total_targets == 0:
            runner.status = ScannerRunStatus.COMPLETED
        elif completed_targets == total_targets:
            runner.status = ScannerRunStatus.COMPLETED
            runner.error_message = None
        elif failed_targets == total_targets:
            runner.status = ScannerRunStatus.FAILED
            runner.error_message = last_error or "All targets failed"
        else:
            runner.status = ScannerRunStatus.PARTIAL
            runner.error_message = (
                f"{failed_targets} of {total_targets} target(s) failed: {last_error}"
            )

        runner.completed_at = datetime.now(UTC)
        runner.duration_seconds = (runner.completed_at - start_time).total_seconds()

    # 1. Deterministic deduplication
    deduped = deduplicate_findings(all_findings)

    # 2. Intelligent cross-scanner correlation
    correlation_groups = correlate_findings(deduped, scan_id)

    # 3. Confidence scoring v2
    deduped = adjust_confidence(deduped)

    # Synchronize correlation group confidence with adjusted findings
    for cg in correlation_groups:
        if cg.findings:
            cg.confidence = max(cg.confidence, max(f.confidence for f in cg.findings))

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

            evidences_to_save = nf.evidences or ([nf.raw_data] if nf.raw_data else [])
            for ev_data in evidences_to_save:
                evidence = FindingEvidence(
                    finding_id=finding.id,
                    scanner_name=nf.scanner_name,
                    raw_data=ev_data,
                )
                session.add(evidence)

    scan.status = ScanStatus.COMPLETED
    scan.risk_gate = risk_gate
    scan.completed_at = datetime.now(UTC)
    await session.commit()
    logger.info(
        "Scan %s completed: %d findings, %d correlation groups, risk_gate=%s",
        scan_id,
        len(deduped),
        len(correlation_groups),
        risk_gate.value,
    )
