"""Mantis safe-analysis advisory integration service.

Executes Google Mantis safe analysis (AgentCapability.REVIEW only) as an opt-in
advisory pipeline step. All findings are strictly advisory:
- Isolated from deterministic deduplication, correlation, confidence adjustment, and risk gate.
- Persisted with correlation_group_id=None, status=OPEN, evidence_level=SINGLE_SOURCE.
- Fail-open execution: Mantis runtime/provider failures never fail the main scan.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.base import AgentCapability
from app.agents.mantis_runtime import MantisSafeRuntime
from app.core.config import Settings, get_settings
from app.models.enums import EvidenceLevel, FindingStatus, ScanMode, ScannerRunStatus
from app.models.finding import Finding, FindingEvidence
from app.models.scan import Scan
from app.models.scanner_run import ScannerRun
from app.security.runner import redact_secrets
from app.services.agentic_corroboration import MantisCorroborationCandidate

logger = logging.getLogger(__name__)


def _normalize_file_path(
    file_path: str | None,
    target_path: Path,
    workspace_root: Path,
) -> str | None:
    """Normalize finding file_path relative to workspace_root."""
    if not file_path:
        return file_path
    p = Path(file_path)
    if not p.is_absolute():
        p = (target_path / p).resolve()
    try:
        return str(p.relative_to(workspace_root.resolve()))
    except ValueError:
        return file_path


@dataclass
class MantisAdvisoryResult:
    """Structured execution outcome of the Mantis advisory review stage."""

    attempted: bool = False
    available: bool = False
    status: str = ScannerRunStatus.NOT_APPLICABLE.value
    findings: list[Finding] = field(default_factory=list)
    summary: str = ""
    analysis: str = ""
    duration_seconds: float = 0.0
    error_message: str | None = None
    corroboration_candidates: list[MantisCorroborationCandidate] = field(
        default_factory=list
    )
    runner: ScannerRun | None = None


async def run_mantis_advisory_analysis(
    scan: Scan,
    project_path: Path,
    session: AsyncSession,
    settings: Settings | None = None,
) -> MantisAdvisoryResult:
    """Execute Mantis safe-analysis review in strict advisory mode.

    Advisory invariants:
    - Never participates in deterministic dedup, correlation, confidence adjustment, or risk gate.
    - Findings are persisted with correlation_group_id=None, status=OPEN, evidence_level=SINGLE_SOURCE.
    - Capability is hardcoded to AgentCapability.REVIEW only.
    - Failure is isolated (fail-open): provider errors never fail the main scan.
    """
    settings = settings or get_settings()

    # Precondition 1: Pipeline flag and global Mantis flag must both be enabled
    if not settings.mantis_pipeline_enabled or not settings.mantis_enabled:
        return MantisAdvisoryResult(
            attempted=False,
            available=False,
            status=ScannerRunStatus.NOT_APPLICABLE.value,
        )

    # Precondition 2: Scan mode must be SOURCE or SOURCE_AND_DAST (never DAST_ONLY)
    if scan.scan_mode == ScanMode.DAST_ONLY:
        return MantisAdvisoryResult(
            attempted=False,
            available=False,
            status=ScannerRunStatus.NOT_APPLICABLE.value,
        )

    # Precondition 3: Execution mode must be strictly 'read_only'
    mode_str = (settings.mantis_execution_mode or "disabled").lower()
    if mode_str != "read_only":
        reason = (
            f"Mantis execution mode '{settings.mantis_execution_mode}' is not eligible "
            "for pipeline auto-run (requires 'read_only')"
        )
        sanitized_reason = redact_secrets(reason)[:1000]
        raw_meta = {
            "capability": AgentCapability.REVIEW.value,
            "advisory": True,
            "risk_gate_eligible": False,
            "findings_count": 0,
            "duration_seconds": 0.0,
            "summary": "",
            "error_class": "IneligibleExecutionMode",
        }
        runner = ScannerRun(
            scan_id=scan.id,
            scanner_name="mantis-advisory-review",
            status=ScannerRunStatus.UNAVAILABLE,
            error_message=sanitized_reason,
            duration_seconds=0.0,
            raw_output=json.dumps(raw_meta),
            completed_at=datetime.now(UTC),
        )
        session.add(runner)
        await session.flush()
        return MantisAdvisoryResult(
            attempted=True,
            available=False,
            status=ScannerRunStatus.UNAVAILABLE.value,
            error_message=sanitized_reason,
            runner=runner,
        )

    # Precondition 4: Check runtime availability
    runtime = MantisSafeRuntime()
    try:
        available, reason = runtime.check_availability(settings)
    except Exception as exc:
        error_class = exc.__class__.__name__
        sanitized_msg = redact_secrets(str(exc))[:1000]
        raw_meta = {
            "capability": AgentCapability.REVIEW.value,
            "advisory": True,
            "risk_gate_eligible": False,
            "findings_count": 0,
            "duration_seconds": 0.0,
            "summary": "",
            "error_class": error_class,
        }
        runner = ScannerRun(
            scan_id=scan.id,
            scanner_name="mantis-advisory-review",
            status=ScannerRunStatus.FAILED,
            error_message=sanitized_msg,
            duration_seconds=0.0,
            raw_output=json.dumps(raw_meta),
            completed_at=datetime.now(UTC),
        )
        session.add(runner)
        await session.flush()
        return MantisAdvisoryResult(
            attempted=True,
            available=False,
            status=ScannerRunStatus.FAILED.value,
            error_message=sanitized_msg,
            runner=runner,
        )

    if not available:
        sanitized_reason = redact_secrets(reason or "")[:1000]
        raw_meta = {
            "capability": AgentCapability.REVIEW.value,
            "advisory": True,
            "risk_gate_eligible": False,
            "findings_count": 0,
            "duration_seconds": 0.0,
            "summary": "",
            "error_class": "RuntimeUnavailable",
        }
        runner = ScannerRun(
            scan_id=scan.id,
            scanner_name="mantis-advisory-review",
            status=ScannerRunStatus.UNAVAILABLE,
            error_message=sanitized_reason,
            duration_seconds=0.0,
            raw_output=json.dumps(raw_meta),
            completed_at=datetime.now(UTC),
        )
        session.add(runner)
        await session.flush()
        return MantisAdvisoryResult(
            attempted=True,
            available=False,
            status=ScannerRunStatus.UNAVAILABLE.value,
            error_message=sanitized_reason,
            runner=runner,
        )

    # Execution record: mark RUNNING
    start_time = datetime.now(UTC)
    runner = ScannerRun(
        scan_id=scan.id,
        scanner_name="mantis-advisory-review",
        status=ScannerRunStatus.RUNNING,
    )
    session.add(runner)
    await session.flush()

    try:
        # AgentCapability.REVIEW strictly hardcoded
        exec_result = await runtime.analyze(
            target_path=project_path,
            capability=AgentCapability.REVIEW,
            settings=settings,
        )
    except Exception as exc:
        duration = (datetime.now(UTC) - start_time).total_seconds()
        logger.warning("Mantis advisory analysis failed: %s", exc.__class__.__name__)
        error_class = exc.__class__.__name__
        error_msg = redact_secrets(str(exc))[:1000]
        raw_meta = {
            "capability": AgentCapability.REVIEW.value,
            "advisory": True,
            "risk_gate_eligible": False,
            "findings_count": 0,
            "duration_seconds": round(duration, 3),
            "summary": "",
            "error_class": error_class,
        }
        runner.status = ScannerRunStatus.FAILED
        runner.error_message = error_msg
        runner.duration_seconds = duration
        runner.raw_output = json.dumps(raw_meta)
        runner.completed_at = datetime.now(UTC)
        await session.flush()
        return MantisAdvisoryResult(
            attempted=True,
            available=True,
            status=ScannerRunStatus.FAILED.value,
            duration_seconds=duration,
            error_message=error_msg,
            runner=runner,
        )

    duration = exec_result.duration_seconds
    summary_snippet = redact_secrets(exec_result.summary or "")[:500]
    pinned_rev = exec_result.metadata.get("mantis_revision") or settings.mantis_revision
    raw_meta = {
        "capability": AgentCapability.REVIEW.value,
        "advisory": True,
        "risk_gate_eligible": False,
        "findings_count": len(exec_result.normalized_findings),
        "duration_seconds": round(duration, 3),
        "summary": summary_snippet,
        "mantis_revision": pinned_rev,
    }
    runner.status = ScannerRunStatus.COMPLETED
    runner.duration_seconds = duration
    runner.raw_output = json.dumps(raw_meta)
    runner.completed_at = datetime.now(UTC)
    await session.flush()

    # Persist findings with strict advisory provenance
    persisted_findings: list[Finding] = []
    candidates: list[MantisCorroborationCandidate] = []
    for nf in exec_result.normalized_findings:
        normalized_path = _normalize_file_path(nf.file_path, project_path, project_path)

        finding = Finding(
            scan_id=scan.id,
            scanner_name="mantis",
            title=nf.title,
            description=nf.description,
            severity=nf.severity,
            confidence=nf.confidence,
            evidence_level=EvidenceLevel.SINGLE_SOURCE,
            correlation_group_id=None,
            cwe=nf.cwe,
            cve=nf.cve,
            file_path=normalized_path,
            line_start=nf.line_start,
            line_end=nf.line_end,
            package_name=nf.package_name,
            installed_version=nf.installed_version,
            fixed_version=nf.fixed_version,
            url=nf.url,
            raw_fingerprint=nf.raw_fingerprint,
            normalized_fingerprint=nf.normalized_fingerprint,
            status=FindingStatus.OPEN,
        )
        session.add(finding)
        await session.flush()

        raw_meta_dict = nf.raw_data if isinstance(nf.raw_data, dict) else {}
        m_status = str(raw_meta_dict.get("mantis_status") or "VALID").strip().upper()
        m_explicit = bool(raw_meta_dict.get("mantis_status_explicit", False))

        candidates.append(
            MantisCorroborationCandidate(
                finding_id=finding.id,
                cwe=finding.cwe,
                cve=finding.cve,
                file_path=finding.file_path,
                line_start=finding.line_start,
                confidence=finding.confidence,
                mantis_status=m_status,
                mantis_status_explicit=m_explicit,
                source_revision=pinned_rev,
            )
        )

        evidences_to_save = nf.evidences or ([nf.raw_data] if nf.raw_data else [])
        for ev_data in evidences_to_save:
            enriched_ev: dict[str, Any] = (
                dict(ev_data) if isinstance(ev_data, dict) else {"raw": ev_data}
            )
            enriched_ev["source_agent"] = "mantis"
            enriched_ev["agentic"] = True
            enriched_ev["advisory"] = True
            enriched_ev["risk_gate_eligible"] = False
            enriched_ev["pipeline_capability"] = "review"
            enriched_ev["source_revision"] = pinned_rev

            evidence = FindingEvidence(
                finding_id=finding.id,
                scanner_name="mantis",
                raw_data=enriched_ev,
            )
            session.add(evidence)

        persisted_findings.append(finding)

    await session.flush()
    return MantisAdvisoryResult(
        attempted=True,
        available=True,
        status=ScannerRunStatus.COMPLETED.value,
        findings=persisted_findings,
        summary=exec_result.summary,
        analysis=exec_result.analysis,
        duration_seconds=duration,
        corroboration_candidates=candidates,
        runner=runner,
    )
