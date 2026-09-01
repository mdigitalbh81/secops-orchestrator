from pathlib import Path
from unittest.mock import patch

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.enums import RiskGate, ScannerRunStatus, ScanStatus
from app.models.finding import Finding
from app.models.project import Project
from app.models.scan import Scan
from app.models.scanner_run import ScannerRun
from app.security.runner import RunResult
from app.services.orchestrator import run_scan


async def test_orchestrator_full_flow(
    db_session: AsyncSession,
    tmp_path: Path,
    semgrep_json: str,
    npm_audit_json: str,
):
    # Create fake project directory
    proj_dir = tmp_path / "my_project"
    proj_dir.mkdir()
    (proj_dir / "package.json").write_text("{}")
    (proj_dir / "app.py").write_text("import pickle")

    project = Project(name="Test Project")
    db_session.add(project)
    await db_session.flush()

    scan = Scan(project_id=project.id, source_path=str(proj_dir))
    db_session.add(scan)
    await db_session.commit()

    # Mock scanner executions
    async def mock_run_command(argv, cwd=None, config=None):
        tool = argv[0]
        if tool == "semgrep":
            if "--version" in argv:
                return RunResult(return_code=0, stdout="1.70.0", stderr="")
            return RunResult(return_code=0, stdout=semgrep_json, stderr="")
        elif tool == "npm":
            if "--version" in argv:
                return RunResult(return_code=0, stdout="10.0.0", stderr="")
            return RunResult(return_code=1, stdout=npm_audit_json, stderr="")
        elif tool in ("pip-audit", "trivy"):
            if "--version" in argv:
                return RunResult(return_code=0, stdout="1.0.0", stderr="")
            return RunResult(return_code=0, stdout="{}", stderr="")
        return RunResult(return_code=-1, stdout="", stderr="Unknown tool")

    with (
        patch("app.scanners.base.run_command", side_effect=mock_run_command),
        patch("app.scanners.semgrep.run_command", side_effect=mock_run_command),
        patch("app.scanners.npm_audit.run_command", side_effect=mock_run_command),
        patch("app.scanners.pip_audit.run_command", side_effect=mock_run_command),
        patch("app.scanners.trivy.run_command", side_effect=mock_run_command),
    ):
        await run_scan(scan.id, db_session)

    # Verify scan completed
    await db_session.refresh(scan)
    assert scan.status == ScanStatus.COMPLETED
    assert scan.risk_gate == RiskGate.BLOCKED  # axios critical vulnerability

    # Verify scanner runs
    runs = (
        (await db_session.execute(select(ScannerRun).where(ScannerRun.scan_id == scan.id)))
        .scalars()
        .all()
    )
    statuses = {r.scanner_name: r.status for r in runs}
    assert statuses["semgrep"] == ScannerRunStatus.COMPLETED
    assert statuses["npm-audit"] == ScannerRunStatus.COMPLETED
    assert statuses["pip-audit"] == ScannerRunStatus.NOT_APPLICABLE
    assert statuses["trivy"] == ScannerRunStatus.NOT_APPLICABLE

    # Verify findings persisted
    findings = (
        (await db_session.execute(select(Finding).where(Finding.scan_id == scan.id)))
        .scalars()
        .all()
    )
    assert len(findings) > 0


async def test_orchestrator_scanner_failure_does_not_break_scan(
    db_session: AsyncSession,
    tmp_path: Path,
    semgrep_json: str,
):
    proj_dir = tmp_path / "failing_project"
    proj_dir.mkdir()
    (proj_dir / "package.json").write_text("{}")

    project = Project(name="Failing Scanner Project")
    db_session.add(project)
    await db_session.flush()

    scan = Scan(project_id=project.id, source_path=str(proj_dir))
    db_session.add(scan)
    await db_session.commit()

    async def mock_run_command(argv, cwd=None, config=None):
        tool = argv[0]
        if tool == "semgrep":
            if "--version" in argv:
                return RunResult(return_code=0, stdout="1.70.0", stderr="")
            return RunResult(return_code=0, stdout=semgrep_json, stderr="")
        elif tool == "npm":
            if "--version" in argv:
                return RunResult(return_code=0, stdout="10.0.0", stderr="")
            raise RuntimeError("NPM crashed unexpectedly")
        return RunResult(return_code=-1, stdout="", stderr="tool not found")

    with (
        patch("app.scanners.base.run_command", side_effect=mock_run_command),
        patch("app.scanners.semgrep.run_command", side_effect=mock_run_command),
        patch("app.scanners.npm_audit.run_command", side_effect=mock_run_command),
        patch("app.scanners.pip_audit.run_command", side_effect=mock_run_command),
        patch("app.scanners.trivy.run_command", side_effect=mock_run_command),
    ):
        await run_scan(scan.id, db_session)

    await db_session.refresh(scan)
    assert scan.status == ScanStatus.COMPLETED

    runs = (
        (await db_session.execute(select(ScannerRun).where(ScannerRun.scan_id == scan.id)))
        .scalars()
        .all()
    )
    statuses = {r.scanner_name: r.status for r in runs}
    assert statuses["semgrep"] == ScannerRunStatus.COMPLETED
    assert statuses["npm-audit"] == ScannerRunStatus.FAILED
