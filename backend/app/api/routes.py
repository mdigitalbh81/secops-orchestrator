"""FastAPI API routes."""
from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.db.session import get_db
from app.models.enums import Severity
from app.models.finding import Finding
from app.models.project import Project
from app.models.scan import Scan
from app.models.scanner_run import ScannerRun
from app.schemas.finding import FindingResponse
from app.schemas.project import ProjectCreate, ProjectResponse
from app.schemas.scan import ScanCreate, ScanResponse
from app.schemas.scanner_run import ScannerRunResponse
from app.schemas.summary import ScanSummary, SeverityTotals
from app.security.runner import RunnerSecurityError, validate_path
from app.workers.scan_worker import enqueue_scan

router = APIRouter(prefix="/api")


@router.post("/projects", response_model=ProjectResponse, status_code=201)
async def create_project(
    payload: ProjectCreate,
    db: AsyncSession = Depends(get_db),
):
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
async def create_scan(
    payload: ScanCreate,
    db: AsyncSession = Depends(get_db),
):
    # Verify project exists
    project = await db.get(Project, payload.project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")

    settings = get_settings()
    try:
        validated_path = validate_path(
            Path(payload.source_path), [settings.allowed_workspace_root]
        )
    except RunnerSecurityError as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid source_path: {exc}",
        ) from exc

    scan = Scan(
        project_id=payload.project_id,
        source_path=str(validated_path),
    )
    db.add(scan)
    await db.flush()
    await db.refresh(scan)

    # Commit before enqueuing so the worker can see the scan
    await db.commit()

    await enqueue_scan(scan.id)
    return scan


@router.get("/scans/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    scan = await db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.get("/scans/{scan_id}/scanner-runs", response_model=list[ScannerRunResponse])
async def get_scanner_runs(scan_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(ScannerRun).where(ScannerRun.scan_id == scan_id)
    )
    return result.scalars().all()


@router.get("/scans/{scan_id}/findings", response_model=list[FindingResponse])
async def get_findings(scan_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Finding).where(Finding.scan_id == scan_id)
    )
    return result.scalars().all()


@router.get("/scans/{scan_id}/summary", response_model=ScanSummary)
async def get_scan_summary(scan_id: str, db: AsyncSession = Depends(get_db)):
    scan = await db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Count findings by severity
    findings_result = await db.execute(
        select(Finding).where(Finding.scan_id == scan_id)
    )
    findings = findings_result.scalars().all()

    totals = SeverityTotals()
    for f in findings:
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

    # Scanner run statuses
    runs_result = await db.execute(
        select(ScannerRun).where(ScannerRun.scan_id == scan_id)
    )
    runs = runs_result.scalars().all()
    scanner_runs = {r.scanner_name: r.status.value.lower() for r in runs}

    return ScanSummary(
        scan_id=scan_id,
        status=scan.status,
        risk_gate=scan.risk_gate,
        totals=totals,
        scanner_runs=scanner_runs,
    )
