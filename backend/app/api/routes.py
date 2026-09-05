"""FastAPI API routes."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.db.session import get_db
from app.models.correlation import CorrelationGroup
from app.models.enums import FindingStatus, Severity
from app.models.finding import Finding
from app.models.project import Project
from app.models.scan import Scan
from app.models.scanner_run import ScannerRun
from app.schemas.correlation import CorrelationGroupResponse
from app.schemas.disposition import (
    CurrentDispositionResponse,
    DispositionEventResponse,
    DispositionRequest,
    DispositionResponse,
)
from app.schemas.finding import FindingResponse
from app.schemas.project import ProjectCreate, ProjectResponse
from app.schemas.scan import ScanCreate, ScanResponse
from app.schemas.scanner_run import ScannerRunResponse
from app.schemas.summary import EvidenceSummary, ScanSummary, SeverityTotals
from app.security.dast_validator import validate_dast_url
from app.security.runner import RunnerSecurityError, validate_path
from app.services.finding_disposition import (
    ALLOWED_DISPOSITIONS,
    get_disposition_history,
    get_finding_disposition,
    resolve_expired_dispositions,
    set_disposition,
)
from app.workers.scan_worker import enqueue_scan

router = APIRouter(prefix="/api")


@router.post("/projects", response_model=ProjectResponse, status_code=201)
async def create_project(payload: ProjectCreate, db: AsyncSession = Depends(get_db)) -> Project:
    project = Project(
        name=payload.name,
        repository_url=payload.repository_url,
        description=payload.description,
    )
    db.add(project)
    await db.flush()
    await db.refresh(project)
    return project


@router.post("/scans", response_model=ScanResponse, status_code=202)
async def create_scan(payload: ScanCreate, db: AsyncSession = Depends(get_db)) -> Scan:
    # Verify project exists
    project = await db.get(Project, payload.project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")

    settings = get_settings()
    try:
        validated_path = validate_path(Path(payload.source_path), [settings.allowed_workspace_root])
    except RunnerSecurityError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid source_path: {exc}") from exc

    validated_target_url: str | None = None
    if payload.target_url:
        try:
            validated_target_url = validate_dast_url(
                payload.target_url,
                allowed_hosts=settings.get_dast_allowed_hosts(),
                enforce_allowlist=settings.dast_enforce_host_allowlist,
            )
        except RunnerSecurityError as exc:
            raise HTTPException(status_code=400, detail=f"Invalid target_url: {exc}") from exc

    scan = Scan(
        project_id=payload.project_id,
        source_path=str(validated_path),
        target_url=validated_target_url,
    )
    db.add(scan)
    await db.flush()
    await db.refresh(scan)
    # Commit before enqueuing so the worker can see the scan
    await db.commit()
    await enqueue_scan(scan.id)
    return scan


@router.get("/scans/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: str, db: AsyncSession = Depends(get_db)) -> Scan:
    scan = await db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    await resolve_expired_dispositions(db, scan.project_id)
    await db.commit()
    await db.refresh(scan)
    return scan


@router.get("/scans/{scan_id}/scanner-runs", response_model=list[ScannerRunResponse])
async def get_scanner_runs(scan_id: str, db: AsyncSession = Depends(get_db)) -> list[ScannerRun]:
    result = await db.execute(select(ScannerRun).where(ScannerRun.scan_id == scan_id))
    return list(result.scalars().all())


@router.get("/scans/{scan_id}/findings", response_model=list[FindingResponse])
async def get_findings(scan_id: str, db: AsyncSession = Depends(get_db)) -> list[Finding]:
    result = await db.execute(select(Finding).where(Finding.scan_id == scan_id))
    return list(result.scalars().all())


@router.get("/scans/{scan_id}/correlations", response_model=list[CorrelationGroupResponse])
async def get_correlations(
    scan_id: str, db: AsyncSession = Depends(get_db)
) -> list[CorrelationGroup]:
    result = await db.execute(select(CorrelationGroup).where(CorrelationGroup.scan_id == scan_id))
    return list(result.scalars().all())


@router.get(
    "/scans/{scan_id}/correlations/{correlation_id}",
    response_model=CorrelationGroupResponse,
)
async def get_correlation_detail(
    scan_id: str,
    correlation_id: str,
    db: AsyncSession = Depends(get_db),
) -> CorrelationGroup:
    result = await db.execute(
        select(CorrelationGroup).where(
            CorrelationGroup.scan_id == scan_id,
            CorrelationGroup.id == correlation_id,
        )
    )
    group = result.scalar_one_or_none()
    if group is None:
        raise HTTPException(status_code=404, detail="Correlation group not found")
    return group


@router.get("/scans/{scan_id}/evidence-summary", response_model=EvidenceSummary)
async def get_evidence_summary(scan_id: str, db: AsyncSession = Depends(get_db)) -> EvidenceSummary:
    scan = await db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings_result = await db.execute(select(Finding).where(Finding.scan_id == scan_id))
    findings = list(findings_result.scalars().all())

    corr_result = await db.execute(
        select(CorrelationGroup).where(CorrelationGroup.scan_id == scan_id)
    )
    correlations = list(corr_result.scalars().all())

    evidence_counts: dict[str, int] = {}
    single_count = 0
    corroborated_count = 0
    runtime_count = 0
    for f in findings:
        lvl = str(
            f.evidence_level.value if hasattr(f.evidence_level, "value") else f.evidence_level
        )
        evidence_counts[lvl] = evidence_counts.get(lvl, 0) + 1
        if lvl == "SINGLE_SOURCE":
            single_count += 1
        elif lvl == "CORROBORATED_STATIC":
            corroborated_count += 1
        elif lvl == "RUNTIME_VALIDATED":
            runtime_count += 1

    return EvidenceSummary(
        scan_id=scan_id,
        total_findings=len(findings),
        total_correlations=len(correlations),
        single_source_count=single_count,
        corroborated_static_count=corroborated_count,
        runtime_validated_count=runtime_count,
        evidence_levels=evidence_counts,
    )


@router.get("/scans/{scan_id}/summary", response_model=ScanSummary)
async def get_scan_summary(scan_id: str, db: AsyncSession = Depends(get_db)) -> ScanSummary:
    scan = await db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    await resolve_expired_dispositions(db, scan.project_id)
    await db.commit()
    await db.refresh(scan)

    # Count findings by severity
    findings_result = await db.execute(select(Finding).where(Finding.scan_id == scan_id))
    findings = list(findings_result.scalars().all())

    totals = SeverityTotals()
    evidence_levels: dict[str, int] = {}
    for f in findings:
        lvl = str(
            f.evidence_level.value if hasattr(f.evidence_level, "value") else f.evidence_level
        )
        evidence_levels[lvl] = evidence_levels.get(lvl, 0) + 1
        match f.severity:
            case Severity.CRITICAL:
                totals.critical += 1
            case Severity.HIGH:
                totals.high += 1
            case Severity.MEDIUM:
                totals.medium += 1
            case Severity.LOW:
                totals.low += 1
            case Severity.INFO:
                totals.info += 1
            case _:
                totals.unknown += 1

    # Correlated totals
    corr_result = await db.execute(
        select(CorrelationGroup).where(CorrelationGroup.scan_id == scan_id)
    )
    correlations = list(corr_result.scalars().all())

    corr_totals = SeverityTotals()
    for cg in correlations:
        match cg.severity:
            case Severity.CRITICAL:
                corr_totals.critical += 1
            case Severity.HIGH:
                corr_totals.high += 1
            case Severity.MEDIUM:
                corr_totals.medium += 1
            case Severity.LOW:
                corr_totals.low += 1
            case Severity.INFO:
                corr_totals.info += 1
            case _:
                corr_totals.unknown += 1

    # Scanner run statuses
    runs_result = await db.execute(select(ScannerRun).where(ScannerRun.scan_id == scan_id))
    runs = list(runs_result.scalars().all())
    scanner_runs = {r.scanner_name: r.status.value.lower() for r in runs}

    # Disposition status counts
    actionable_count = sum(
        1 for f in findings if FindingStatus(f.status) == FindingStatus.OPEN
    )
    false_positive_count = sum(
        1 for f in findings if FindingStatus(f.status) == FindingStatus.FALSE_POSITIVE
    )
    accepted_risk_count = sum(
        1 for f in findings if FindingStatus(f.status) == FindingStatus.ACCEPTED_RISK
    )
    accepted_by_design_count = sum(
        1 for f in findings if FindingStatus(f.status) == FindingStatus.ACCEPTED_BY_DESIGN
    )
    fixed_count = sum(
        1 for f in findings if FindingStatus(f.status) == FindingStatus.FIXED
    )

    return ScanSummary(
        scan_id=scan_id,
        status=scan.status,
        risk_gate=scan.risk_gate,
        totals=totals,
        correlated_totals=corr_totals,
        evidence_levels=evidence_levels,
        scanner_runs=scanner_runs,
        actionable_count=actionable_count,
        false_positive_count=false_positive_count,
        accepted_risk_count=accepted_risk_count,
        accepted_by_design_count=accepted_by_design_count,
        fixed_count=fixed_count,
    )


@router.patch(
    "/findings/{finding_id}/disposition",
    response_model=DispositionResponse,
)
async def patch_finding_disposition(
    finding_id: str,
    payload: DispositionRequest,
    db: AsyncSession = Depends(get_db),
) -> dict:
    finding = await db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")

    if payload.status not in ALLOWED_DISPOSITIONS:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid status. Allowed: {sorted(s.value for s in ALLOWED_DISPOSITIONS)}",
        )

    if payload.expires_at is not None and payload.expires_at <= datetime.now(UTC):
        raise HTTPException(status_code=422, detail="expires_at must be in the future")

    updated_finding, disposition, event, new_risk_gate = await set_disposition(
        session=db,
        finding=finding,
        new_status=payload.status,
        justification=payload.justification,
        actor=payload.actor,
        expires_at=payload.expires_at,
    )
    await db.commit()
    await db.refresh(updated_finding)

    scan = await db.get(Scan, updated_finding.scan_id)

    return {
        "finding_id": updated_finding.id,
        "status": updated_finding.status,
        "justification": payload.justification,
        "actor": payload.actor,
        "expires_at": payload.expires_at,
        "updated_at": event.created_at,
        "scan_id": updated_finding.scan_id,
        "scan_risk_gate": scan.risk_gate if scan else None,
    }


@router.get(
    "/findings/{finding_id}/disposition-history",
    response_model=list[DispositionEventResponse],
)
async def get_finding_disposition_history(
    finding_id: str,
    db: AsyncSession = Depends(get_db),
) -> list:
    finding = await db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    scan = await db.get(Scan, finding.scan_id)
    if scan:
        await resolve_expired_dispositions(db, scan.project_id)
        await db.commit()
    return await get_disposition_history(db, finding_id)


@router.get(
    "/findings/{finding_id}/disposition",
    response_model=CurrentDispositionResponse | None,
)
async def get_finding_current_disposition(
    finding_id: str,
    db: AsyncSession = Depends(get_db),
):
    finding = await db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    scan = await db.get(Scan, finding.scan_id)
    if scan:
        await resolve_expired_dispositions(db, scan.project_id)
        await db.commit()
        await db.refresh(finding)
    disp = await get_finding_disposition(db, finding)
    if disp is None:
        return None
    return disp
