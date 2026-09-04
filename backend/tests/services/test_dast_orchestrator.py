from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.enums import EvidenceLevel, RiskGate, ScannerRunStatus, ScanStatus, Severity
from app.models.finding import Finding
from app.models.project import Project
from app.models.scan import Scan
from app.models.scanner_run import ScannerRun
from app.scanners.base import NormalizedFinding
from app.security.runner import RunResult
from app.services.orchestrator import run_scan


@pytest.mark.asyncio
async def test_sast_scan_without_target_url_marks_dast_not_applicable(
    db_session: AsyncSession, test_settings
):
    project = Project(name="Static Only Project")
    db_session.add(project)
    await db_session.flush()

    repo_dir = test_settings.workspace_base / "static_repo"
    repo_dir.mkdir(parents=True, exist_ok=True)
    (repo_dir / "app.py").write_text("print('hello')")

    scan = Scan(
        project_id=project.id,
        source_path=str(repo_dir),
        target_url=None,  # No DAST target URL
    )
    db_session.add(scan)
    await db_session.commit()

    with patch("app.services.orchestrator.get_all_scanners") as mock_scanners:
        mock_semgrep = MagicMock()
        mock_semgrep.name = "semgrep"
        mock_semgrep.detect_applicability.return_value = True
        mock_semgrep.is_available = AsyncMock(return_value=True)
        mock_semgrep.execute = AsyncMock(
            return_value=RunResult(return_code=0, stdout="{}", stderr="")
        )
        mock_semgrep.parse_result.return_value = []
        mock_semgrep.normalize_findings.return_value = []

        mock_zap = MagicMock()
        mock_zap.name = "zap"
        mock_zap.detect_applicability.return_value = False  # Not applicable without target_url
        mock_zap.is_available = AsyncMock(return_value=False)

        mock_nuclei = MagicMock()
        mock_nuclei.name = "nuclei"
        mock_nuclei.detect_applicability.return_value = False  # Not applicable without target_url
        mock_nuclei.is_available = AsyncMock(return_value=False)

        mock_scanners.return_value = [mock_semgrep, mock_zap, mock_nuclei]

        await run_scan(scan.id, db_session)

    await db_session.refresh(scan)
    assert scan.status == ScanStatus.COMPLETED
    assert scan.risk_gate == RiskGate.PASS

    # Verify scanner runs
    res = await db_session.execute(select(ScannerRun).where(ScannerRun.scan_id == scan.id))
    runs = {r.scanner_name: r.status for r in res.scalars().all()}

    assert runs.get("semgrep") == ScannerRunStatus.COMPLETED
    assert runs.get("zap") == ScannerRunStatus.NOT_APPLICABLE
    assert runs.get("nuclei") == ScannerRunStatus.NOT_APPLICABLE


@pytest.mark.asyncio
async def test_dast_scanner_unavailable_when_binary_missing(
    db_session: AsyncSession, test_settings
):
    project = Project(name="DAST Unavailable Project")
    db_session.add(project)
    await db_session.flush()

    repo_dir = test_settings.workspace_base / "dast_repo"
    repo_dir.mkdir(parents=True, exist_ok=True)

    scan = Scan(
        project_id=project.id,
        source_path=str(repo_dir),
        target_url="http://staging-app:3000",
    )
    db_session.add(scan)
    await db_session.commit()

    with patch("app.services.orchestrator.get_all_scanners") as mock_scanners:
        mock_zap = MagicMock()
        mock_zap.name = "zap"
        mock_zap.detect_applicability.return_value = True
        mock_zap.is_available = AsyncMock(return_value=False)  # Missing binary

        mock_scanners.return_value = [mock_zap]

        await run_scan(scan.id, db_session)

    await db_session.refresh(scan)
    assert scan.status == ScanStatus.COMPLETED

    res = await db_session.execute(select(ScannerRun).where(ScannerRun.scan_id == scan.id))
    runs = {r.scanner_name: r for r in res.scalars().all()}
    assert runs["zap"].status == ScannerRunStatus.UNAVAILABLE
    assert "not installed" in runs["zap"].error_message


@pytest.mark.asyncio
async def test_dast_failure_preserves_static_findings(db_session: AsyncSession, test_settings):
    project = Project(name="Mixed Scan Project")
    db_session.add(project)
    await db_session.flush()

    repo_dir = test_settings.workspace_base / "mixed_repo"
    repo_dir.mkdir(parents=True, exist_ok=True)

    scan = Scan(
        project_id=project.id,
        source_path=str(repo_dir),
        target_url="http://staging-app:3000",
    )
    db_session.add(scan)
    await db_session.commit()

    static_finding = NormalizedFinding(
        title="Hardcoded Secret",
        description="Found API key in code",
        severity=Severity.HIGH,
        confidence=0.70,
        scanner_name="semgrep",
        cwe="CWE-798",
        file_path="config.py",
        line_start=10,
        line_end=10,
        evidence_level=EvidenceLevel.SINGLE_SOURCE,
    )

    with patch("app.services.orchestrator.get_all_scanners") as mock_scanners:
        # Semgrep succeeds with a finding
        mock_semgrep = MagicMock()
        mock_semgrep.name = "semgrep"
        mock_semgrep.detect_applicability.return_value = True
        mock_semgrep.is_available = AsyncMock(return_value=True)
        mock_semgrep.execute = AsyncMock(
            return_value=RunResult(return_code=0, stdout="{}", stderr="")
        )
        mock_semgrep.parse_result.return_value = [{}]
        mock_semgrep.normalize_findings.return_value = [static_finding]

        # ZAP fails (e.g. network timeout or crash)
        mock_zap = MagicMock()
        mock_zap.name = "zap"
        mock_zap.detect_applicability.return_value = True
        mock_zap.is_available = AsyncMock(return_value=True)
        mock_zap.execute = AsyncMock(
            return_value=RunResult(return_code=1, stdout="", stderr="Connection refused")
        )
        mock_zap.parse_result.return_value = []
        mock_zap.normalize_findings.return_value = []

        mock_scanners.return_value = [mock_semgrep, mock_zap]

        await run_scan(scan.id, db_session)

    await db_session.refresh(scan)
    assert scan.status == ScanStatus.COMPLETED

    # Verify static finding was persisted and NOT lost
    res_f = await db_session.execute(select(Finding).where(Finding.scan_id == scan.id))
    findings = list(res_f.scalars().all())
    assert len(findings) == 1
    assert findings[0].title == "Hardcoded Secret"
    assert findings[0].scanner_name == "semgrep"

    # Verify runner statuses
    res_r = await db_session.execute(select(ScannerRun).where(ScannerRun.scan_id == scan.id))
    runs = {r.scanner_name: r for r in res_r.scalars().all()}
    assert runs["semgrep"].status == ScannerRunStatus.COMPLETED
    assert runs["zap"].status == ScannerRunStatus.FAILED

@pytest.mark.asyncio
async def test_nuclei_unavailable_does_not_abort_zap_and_sast(
    db_session: AsyncSession, test_settings
):
    """When Nuclei is UNAVAILABLE, ZAP and SAST continue and complete successfully."""
    project = Project(name="Nuclei Unavailable Project")
    db_session.add(project)
    await db_session.flush()

    repo_dir = test_settings.workspace_base / "nuclei_unavail_repo"
    repo_dir.mkdir(parents=True, exist_ok=True)

    scan = Scan(
        project_id=project.id,
        source_path=str(repo_dir),
        target_url="http://staging-app:3000",
    )
    db_session.add(scan)
    await db_session.commit()

    zap_finding = NormalizedFinding(
        title="Missing Security Headers",
        description="X-Frame-Options missing",
        severity=Severity.LOW,
        confidence=0.85,
        scanner_name="zap",
        cwe="CWE-1021",
        url="http://staging-app:3000/",
        evidence_level=EvidenceLevel.RUNTIME_VALIDATED,
    )

    with patch("app.services.orchestrator.get_all_scanners") as mock_scanners:
        mock_semgrep = MagicMock()
        mock_semgrep.name = "semgrep"
        mock_semgrep.detect_applicability.return_value = True
        mock_semgrep.is_available = AsyncMock(return_value=True)
        mock_semgrep.execute = AsyncMock(
            return_value=RunResult(return_code=0, stdout="{}", stderr="")
        )
        mock_semgrep.parse_result.return_value = []
        mock_semgrep.normalize_findings.return_value = []

        # Nuclei unavailable
        mock_nuclei = MagicMock()
        mock_nuclei.name = "nuclei"
        mock_nuclei.detect_applicability.return_value = True
        mock_nuclei.is_available = AsyncMock(return_value=False)

        # ZAP available & completed
        mock_zap = MagicMock()
        mock_zap.name = "zap"
        mock_zap.detect_applicability.return_value = True
        mock_zap.is_available = AsyncMock(return_value=True)
        mock_zap.execute = AsyncMock(
            return_value=RunResult(return_code=0, stdout='{"alerts": [{}]}', stderr="")
        )
        mock_zap.parse_result.return_value = [{}]
        mock_zap.normalize_findings.return_value = [zap_finding]

        mock_scanners.return_value = [mock_semgrep, mock_nuclei, mock_zap]

        await run_scan(scan.id, db_session)

    await db_session.refresh(scan)
    assert scan.status == ScanStatus.COMPLETED

    res_r = await db_session.execute(
        select(ScannerRun).where(ScannerRun.scan_id == scan.id)
    )
    runs = {r.scanner_name: r for r in res_r.scalars().all()}
    assert runs["nuclei"].status == ScannerRunStatus.UNAVAILABLE
    assert runs["zap"].status == ScannerRunStatus.COMPLETED
    assert runs["semgrep"].status == ScannerRunStatus.COMPLETED

    res_f = await db_session.execute(select(Finding).where(Finding.scan_id == scan.id))
    findings = list(res_f.scalars().all())
    assert len(findings) == 1
    assert findings[0].scanner_name == "zap"


@pytest.mark.asyncio
async def test_zap_unavailable_does_not_abort_nuclei_and_sast(
    db_session: AsyncSession, test_settings
):
    """When ZAP is UNAVAILABLE, Nuclei and SAST continue and complete successfully."""
    project = Project(name="ZAP Unavailable Project")
    db_session.add(project)
    await db_session.flush()

    repo_dir = test_settings.workspace_base / "zap_unavail_repo"
    repo_dir.mkdir(parents=True, exist_ok=True)

    scan = Scan(
        project_id=project.id,
        source_path=str(repo_dir),
        target_url="http://staging-app:3000",
    )
    db_session.add(scan)
    await db_session.commit()

    nuclei_finding = NormalizedFinding(
        title="Swagger API Detect",
        description="Public swagger exposed",
        severity=Severity.INFO,
        confidence=0.85,
        scanner_name="nuclei",
        cwe="CWE-200",
        url="http://staging-app:3000/docs",
        evidence_level=EvidenceLevel.RUNTIME_VALIDATED,
    )

    with patch("app.services.orchestrator.get_all_scanners") as mock_scanners:
        mock_semgrep = MagicMock()
        mock_semgrep.name = "semgrep"
        mock_semgrep.detect_applicability.return_value = True
        mock_semgrep.is_available = AsyncMock(return_value=True)
        mock_semgrep.execute = AsyncMock(
            return_value=RunResult(return_code=0, stdout="{}", stderr="")
        )
        mock_semgrep.parse_result.return_value = []
        mock_semgrep.normalize_findings.return_value = []

        # ZAP unavailable
        mock_zap = MagicMock()
        mock_zap.name = "zap"
        mock_zap.detect_applicability.return_value = True
        mock_zap.is_available = AsyncMock(return_value=False)

        # Nuclei available & completed
        mock_nuclei = MagicMock()
        mock_nuclei.name = "nuclei"
        mock_nuclei.detect_applicability.return_value = True
        mock_nuclei.is_available = AsyncMock(return_value=True)
        mock_nuclei.execute = AsyncMock(
            return_value=RunResult(return_code=0, stdout='{"template": "test"}', stderr="")
        )
        mock_nuclei.parse_result.return_value = [{}]
        mock_nuclei.normalize_findings.return_value = [nuclei_finding]

        mock_scanners.return_value = [mock_semgrep, mock_zap, mock_nuclei]

        await run_scan(scan.id, db_session)

    await db_session.refresh(scan)
    assert scan.status == ScanStatus.COMPLETED

    res_r = await db_session.execute(
        select(ScannerRun).where(ScannerRun.scan_id == scan.id)
    )
    runs = {r.scanner_name: r for r in res_r.scalars().all()}
    assert runs["zap"].status == ScannerRunStatus.UNAVAILABLE
    assert runs["nuclei"].status == ScannerRunStatus.COMPLETED
    assert runs["semgrep"].status == ScannerRunStatus.COMPLETED

    res_f = await db_session.execute(select(Finding).where(Finding.scan_id == scan.id))
    findings = list(res_f.scalars().all())
    assert len(findings) == 1
    assert findings[0].scanner_name == "nuclei"
