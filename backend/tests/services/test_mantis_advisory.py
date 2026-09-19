"""Comprehensive unit and integration tests for Mantis advisory pipeline stage."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.base import AgentCapability
from app.agents.mantis import MantisAdapter
from app.agents.mantis_runtime import (
    MantisExecutionResult,
    MantisProviderError,
    MantisSafeRuntime,
    MantisValidationError,
)
from app.core.config import Settings
from app.models.enums import (
    EvidenceLevel,
    FindingStatus,
    RiskGate,
    ScanMode,
    ScannerRunStatus,
    ScanStatus,
    Severity,
)
from app.models.finding import Finding
from app.models.project import Project
from app.models.scan import Scan
from app.models.scanner_run import ScannerRun
from app.scanners.base import NormalizedFinding
from app.schemas.finding import FindingResponse
from app.security.runner import RunResult
from app.services.mantis_advisory import run_mantis_advisory_analysis
from app.services.orchestrator import run_scan


def _create_sample_target(workspace: Path) -> Path:
    target = workspace / "sample_app"
    target.mkdir(parents=True, exist_ok=True)
    (target / "main.py").write_text("import pickle\n\ndef load(data):\n    return pickle.loads(data)\n")
    (target / "requirements.txt").write_text("requests==2.25.1\n")
    return target


def _hash_tree(root: Path) -> dict[str, str]:
    hashes = {}
    for p in sorted(root.rglob("*")):
        if p.is_file():
            rel = str(p.relative_to(root))
            hashes[rel] = hashlib.sha256(p.read_bytes()).hexdigest()
    return hashes


@pytest.mark.asyncio
async def test_mantis_advisory_preconditions_pipeline_disabled(
    db_session: AsyncSession, tmp_path: Path
):
    target = _create_sample_target(tmp_path)
    scan = Scan(
        id="scan-advisory-1",
        project_id="proj-1",
        source_path=str(target),
        scan_mode=ScanMode.SOURCE,
    )
    settings = Settings(
        mantis_enabled=True,
        mantis_pipeline_enabled=False,
        mantis_execution_mode="read_only",
    )

    result = await run_mantis_advisory_analysis(
        scan=scan, project_path=target, session=db_session, settings=settings
    )

    assert result.attempted is False
    assert result.available is False
    assert result.status == ScannerRunStatus.NOT_APPLICABLE.value
    runs = (await db_session.execute(select(ScannerRun))).scalars().all()
    assert len(runs) == 0


@pytest.mark.asyncio
async def test_mantis_advisory_preconditions_mantis_disabled(
    db_session: AsyncSession, tmp_path: Path
):
    target = _create_sample_target(tmp_path)
    scan = Scan(
        id="scan-advisory-2",
        project_id="proj-1",
        source_path=str(target),
        scan_mode=ScanMode.SOURCE,
    )
    settings = Settings(
        mantis_enabled=False,
        mantis_pipeline_enabled=True,
        mantis_execution_mode="read_only",
    )

    result = await run_mantis_advisory_analysis(
        scan=scan, project_path=target, session=db_session, settings=settings
    )

    assert result.attempted is False
    assert result.available is False
    assert result.status == ScannerRunStatus.NOT_APPLICABLE.value
    runs = (await db_session.execute(select(ScannerRun))).scalars().all()
    assert len(runs) == 0


@pytest.mark.asyncio
async def test_mantis_advisory_preconditions_dast_only(
    db_session: AsyncSession, tmp_path: Path
):
    target = _create_sample_target(tmp_path)
    scan = Scan(
        id="scan-advisory-3",
        project_id="proj-1",
        source_path=str(target),
        scan_mode=ScanMode.DAST_ONLY,
    )
    settings = Settings(
        mantis_enabled=True,
        mantis_pipeline_enabled=True,
        mantis_execution_mode="read_only",
    )

    result = await run_mantis_advisory_analysis(
        scan=scan, project_path=target, session=db_session, settings=settings
    )

    assert result.attempted is False
    assert result.available is False
    assert result.status == ScannerRunStatus.NOT_APPLICABLE.value
    runs = (await db_session.execute(select(ScannerRun))).scalars().all()
    assert len(runs) == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["disabled", "dry_run", "sandbox", "local"])
async def test_mantis_advisory_ineligible_execution_modes(
    db_session: AsyncSession, tmp_path: Path, mode: str
):
    target = _create_sample_target(tmp_path)
    scan = Scan(
        id=f"scan-mode-{mode}",
        project_id="proj-1",
        source_path=str(target),
        scan_mode=ScanMode.SOURCE,
    )
    settings = Settings(
        mantis_enabled=True,
        mantis_pipeline_enabled=True,
        mantis_execution_mode=mode,
    )

    result = await run_mantis_advisory_analysis(
        scan=scan, project_path=target, session=db_session, settings=settings
    )

    assert result.attempted is True
    assert result.available is False
    assert result.status == ScannerRunStatus.UNAVAILABLE.value
    assert "requires 'read_only'" in (result.error_message or "")

    run = (
        await db_session.execute(
            select(ScannerRun).where(ScannerRun.scan_id == scan.id)
        )
    ).scalar_one()
    assert run.scanner_name == "mantis-advisory-review"
    assert run.status == ScannerRunStatus.UNAVAILABLE
    raw_meta = json.loads(run.raw_output)
    assert raw_meta["capability"] == "review"
    assert raw_meta["advisory"] is True
    assert raw_meta["risk_gate_eligible"] is False


@pytest.mark.asyncio
async def test_mantis_advisory_runtime_unavailable(
    db_session: AsyncSession, tmp_path: Path
):
    target = _create_sample_target(tmp_path)
    scan = Scan(
        id="scan-advisory-unavail",
        project_id="proj-1",
        source_path=str(target),
        scan_mode=ScanMode.SOURCE,
    )
    settings = Settings(
        mantis_enabled=True,
        mantis_pipeline_enabled=True,
        mantis_execution_mode="read_only",
        mantis_root=tmp_path / "nonexistent-mantis",
    )

    result = await run_mantis_advisory_analysis(
        scan=scan, project_path=target, session=db_session, settings=settings
    )

    assert result.attempted is True
    assert result.available is False
    assert result.status == ScannerRunStatus.UNAVAILABLE.value

    run = (
        await db_session.execute(
            select(ScannerRun).where(ScannerRun.scan_id == scan.id)
        )
    ).scalar_one()
    assert run.scanner_name == "mantis-advisory-review"
    assert run.status == ScannerRunStatus.UNAVAILABLE
    raw_meta = json.loads(run.raw_output)
    assert raw_meta["advisory"] is True
    assert raw_meta["risk_gate_eligible"] is False


@pytest.mark.asyncio
async def test_mantis_advisory_success_multiple_findings(
    db_session: AsyncSession, tmp_path: Path
):
    target = _create_sample_target(tmp_path)
    scan = Scan(
        id="scan-advisory-success",
        project_id="proj-1",
        source_path=str(target),
        scan_mode=ScanMode.SOURCE,
    )
    settings = Settings(
        mantis_enabled=True,
        mantis_pipeline_enabled=True,
        mantis_execution_mode="read_only",
    )

    adapter = MantisAdapter()
    raw_items = [
        {
            "id": "mantis-1",
            "title": "Unsafe Deserialization via pickle",
            "description": "Arbitrary code execution risk",
            "severity": "CRITICAL",
            "confidence": 0.60,
            "cwe": "CWE-502",
            "file_path": "main.py",
            "line_start": 4,
            "line_end": 4,
            "mantis_status": "VALID",
        },
        {
            "id": "mantis-2",
            "title": "Outdated Dependency requests",
            "description": "Vulnerable requests version",
            "severity": "MEDIUM",
            "confidence": 0.40,
            "cwe": "CWE-1395",
            "file_path": "requirements.txt",
            "line_start": 1,
            "line_end": 1,
            "mantis_status": "VALID",
        },
        {
            "id": "mantis-3",
            "title": "Information Disclosure in Log",
            "description": "Sensitive details logged",
            "severity": "LOW",
            "confidence": 0.30,
            "cwe": "CWE-532",
            "file_path": "main.py",
            "line_start": 3,
            "line_end": 3,
            "mantis_status": "PROVISIONALLY_VALID",
        },
    ]
    normalized = adapter.ingest_findings(raw_items)
    mock_result = MantisExecutionResult(
        capability=AgentCapability.REVIEW,
        summary="Code review identified 3 potential vulnerabilities.",
        analysis="Detailed analysis text",
        raw_findings=raw_items,
        normalized_findings=normalized,
        metadata={"mantis_revision": "d13c93fb8e9779801711daea0d65fffa133c3b2d"},
        duration_seconds=1.45,
    )

    with (
        patch.object(MantisSafeRuntime, "check_availability", return_value=(True, "available")),
        patch.object(MantisSafeRuntime, "analyze", new_callable=AsyncMock, return_value=mock_result) as mock_analyze,
    ):
        result = await run_mantis_advisory_analysis(
            scan=scan, project_path=target, session=db_session, settings=settings
        )

    mock_analyze.assert_awaited_once_with(
        target_path=target,
        capability=AgentCapability.REVIEW,
        settings=settings,
    )

    assert result.attempted is True
    assert result.status == ScannerRunStatus.COMPLETED.value
    assert len(result.findings) == 3

    persisted_findings = (
        await db_session.execute(
            select(Finding).where(Finding.scan_id == scan.id).order_by(Finding.title)
        )
    ).scalars().all()
    assert len(persisted_findings) == 3

    for f in persisted_findings:
        assert f.scanner_name == "mantis"
        assert f.correlation_group_id is None
        assert f.status == FindingStatus.OPEN
        assert f.evidence_level == EvidenceLevel.SINGLE_SOURCE
        assert f.advisory is True
        assert f.risk_gate_eligible is False

        # Test schema model serialization
        resp = FindingResponse.model_validate(f)
        assert resp.advisory is True
        assert resp.risk_gate_eligible is False

        assert len(f.evidences) >= 1
        ev = f.evidences[0]
        assert ev.scanner_name == "mantis"
        assert ev.raw_data["source_agent"] == "mantis"
        assert ev.raw_data["agentic"] is True
        assert ev.raw_data["advisory"] is True
        assert ev.raw_data["risk_gate_eligible"] is False
        assert ev.raw_data["pipeline_capability"] == "review"
        assert ev.raw_data["source_revision"] == "d13c93fb8e9779801711daea0d65fffa133c3b2d"

    run = (
        await db_session.execute(
            select(ScannerRun).where(ScannerRun.scan_id == scan.id)
        )
    ).scalar_one()
    assert run.scanner_name == "mantis-advisory-review"
    assert run.status == ScannerRunStatus.COMPLETED
    raw_meta = json.loads(run.raw_output)
    assert raw_meta["findings_count"] == 3
    assert raw_meta["advisory"] is True
    assert raw_meta["risk_gate_eligible"] is False


@pytest.mark.asyncio
async def test_mantis_advisory_zero_findings(
    db_session: AsyncSession, tmp_path: Path
):
    target = _create_sample_target(tmp_path)
    scan = Scan(
        id="scan-advisory-zero",
        project_id="proj-1",
        source_path=str(target),
        scan_mode=ScanMode.SOURCE,
    )
    settings = Settings(
        mantis_enabled=True,
        mantis_pipeline_enabled=True,
        mantis_execution_mode="read_only",
    )

    mock_result = MantisExecutionResult(
        capability=AgentCapability.REVIEW,
        summary="No security findings observed.",
        analysis="Review completed cleanly.",
        raw_findings=[],
        normalized_findings=[],
        metadata={"mantis_revision": "d13c93fb8e9779801711daea0d65fffa133c3b2d"},
        duration_seconds=0.8,
    )

    with (
        patch.object(MantisSafeRuntime, "check_availability", return_value=(True, "available")),
        patch.object(MantisSafeRuntime, "analyze", new_callable=AsyncMock, return_value=mock_result),
    ):
        result = await run_mantis_advisory_analysis(
            scan=scan, project_path=target, session=db_session, settings=settings
        )

    assert result.status == ScannerRunStatus.COMPLETED.value
    assert len(result.findings) == 0
    persisted_findings = (
        await db_session.execute(select(Finding).where(Finding.scan_id == scan.id))
    ).scalars().all()
    assert len(persisted_findings) == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "exc_to_raise",
    [
        MantisValidationError("Invalid skill content"),
        MantisProviderError("LLM rate limited (429)"),
        TimeoutError("Request timed out after 120s"),
    ],
)
async def test_mantis_advisory_failure_isolation(
    db_session: AsyncSession, tmp_path: Path, exc_to_raise: Exception
):
    target = _create_sample_target(tmp_path)
    scan = Scan(
        id=f"scan-fail-{exc_to_raise.__class__.__name__}",
        project_id="proj-1",
        source_path=str(target),
        scan_mode=ScanMode.SOURCE,
    )
    settings = Settings(
        mantis_enabled=True,
        mantis_pipeline_enabled=True,
        mantis_execution_mode="read_only",
    )

    with (
        patch.object(MantisSafeRuntime, "check_availability", return_value=(True, "available")),
        patch.object(MantisSafeRuntime, "analyze", new_callable=AsyncMock, side_effect=exc_to_raise),
    ):
        result = await run_mantis_advisory_analysis(
            scan=scan, project_path=target, session=db_session, settings=settings
        )

    assert result.attempted is True
    assert result.status == ScannerRunStatus.FAILED.value
    assert exc_to_raise.__class__.__name__ in (result.error_message or "") or str(exc_to_raise) in (result.error_message or "")

    run = (
        await db_session.execute(
            select(ScannerRun).where(ScannerRun.scan_id == scan.id)
        )
    ).scalar_one()
    assert run.scanner_name == "mantis-advisory-review"
    assert run.status == ScannerRunStatus.FAILED
    raw_meta = json.loads(run.raw_output)
    assert raw_meta["error_class"] == exc_to_raise.__class__.__name__
    assert raw_meta["advisory"] is True
    assert raw_meta["risk_gate_eligible"] is False


@pytest.mark.asyncio
async def test_mantis_advisory_verdicts_all_start_open(
    db_session: AsyncSession, tmp_path: Path
):
    target = _create_sample_target(tmp_path)
    scan = Scan(
        id="scan-verdicts",
        project_id="proj-1",
        source_path=str(target),
        scan_mode=ScanMode.SOURCE,
    )
    settings = Settings(
        mantis_enabled=True,
        mantis_pipeline_enabled=True,
        mantis_execution_mode="read_only",
    )

    adapter = MantisAdapter()
    raw_items = [
        {"title": "FP item", "severity": "HIGH", "mantis_status": "FALSE_POSITIVE", "file_path": "main.py"},
        {"title": "Dup item", "severity": "HIGH", "mantis_status": "DUPLICATE", "file_path": "main.py"},
        {"title": "Valid item", "severity": "HIGH", "mantis_status": "VALID", "file_path": "main.py"},
        {"title": "Prov item", "severity": "HIGH", "mantis_status": "PROVISIONALLY_VALID", "file_path": "main.py"},
        {"title": "Research item", "severity": "HIGH", "mantis_status": "NEEDS_RESEARCH", "file_path": "main.py"},
    ]
    normalized = adapter.ingest_findings(raw_items)
    mock_result = MantisExecutionResult(
        capability=AgentCapability.REVIEW,
        summary="Various verdicts",
        analysis="Analysis",
        raw_findings=raw_items,
        normalized_findings=normalized,
        metadata={"mantis_revision": "d13c93fb8e9779801711daea0d65fffa133c3b2d"},
        duration_seconds=1.0,
    )

    with (
        patch.object(MantisSafeRuntime, "check_availability", return_value=(True, "available")),
        patch.object(MantisSafeRuntime, "analyze", new_callable=AsyncMock, return_value=mock_result),
    ):
        result = await run_mantis_advisory_analysis(
            scan=scan, project_path=target, session=db_session, settings=settings
        )

    for f in result.findings:
        assert f.status == FindingStatus.OPEN
        assert f.evidence_level == EvidenceLevel.SINGLE_SOURCE


@pytest.mark.asyncio
async def test_mantis_advisory_fake_reproduction_claim_remains_single_source(
    db_session: AsyncSession, tmp_path: Path
):
    target = _create_sample_target(tmp_path)
    scan = Scan(
        id="scan-repro-claim",
        project_id="proj-1",
        source_path=str(target),
        scan_mode=ScanMode.SOURCE,
    )
    settings = Settings(
        mantis_enabled=True,
        mantis_pipeline_enabled=True,
        mantis_execution_mode="read_only",
    )

    adapter = MantisAdapter()
    raw_items = [
        {
            "title": "Fake Verified Exploitation",
            "description": "Claiming runtime verification",
            "severity": "CRITICAL",
            "repro_status": "reproduced",
            "verified": True,
            "description_exploit": "confirmed exploit",
            "file_path": "main.py",
        }
    ]
    normalized = adapter.ingest_findings(raw_items)
    # Even if an attacker or rogue adapter altered evidence_level to RUNTIME_VALIDATED:
    normalized[0].evidence_level = EvidenceLevel.RUNTIME_VALIDATED

    mock_result = MantisExecutionResult(
        capability=AgentCapability.REVIEW,
        summary="Claiming repro",
        analysis="Analysis",
        raw_findings=raw_items,
        normalized_findings=normalized,
        metadata={"mantis_revision": "d13c93fb8e9779801711daea0d65fffa133c3b2d"},
        duration_seconds=1.0,
    )

    with (
        patch.object(MantisSafeRuntime, "check_availability", return_value=(True, "available")),
        patch.object(MantisSafeRuntime, "analyze", new_callable=AsyncMock, return_value=mock_result),
    ):
        result = await run_mantis_advisory_analysis(
            scan=scan, project_path=target, session=db_session, settings=settings
        )

    assert len(result.findings) == 1
    persisted = result.findings[0]
    assert persisted.evidence_level == EvidenceLevel.SINGLE_SOURCE
    assert persisted.advisory is True
    assert persisted.risk_gate_eligible is False


@pytest.mark.asyncio
async def test_pipeline_risk_gate_invariant_zero_deterministic_critical_mantis(
    db_session: AsyncSession, tmp_path: Path
):
    """BLOCKING TEST (Section 16):
    Deterministic scanner returns 0 findings.
    Mantis returns CRITICAL (confidence 0.60, status VALID).
    Expected: scan.risk_gate == PASS.
    Mantis CRITICAL is persisted and visible, but DOES NOT block the gate.
    """
    target = _create_sample_target(tmp_path)
    project = Project(name="Project Invariant 1")
    db_session.add(project)
    await db_session.flush()

    scan = Scan(
        project_id=project.id,
        source_path=str(target),
        scan_mode=ScanMode.SOURCE,
    )
    db_session.add(scan)
    await db_session.commit()

    settings = Settings(
        mantis_enabled=True,
        mantis_pipeline_enabled=True,
        mantis_execution_mode="read_only",
        allowed_workspace_root=tmp_path,
    )

    adapter = MantisAdapter()
    mantis_findings_raw = [
        {
            "id": "mantis-crit-1",
            "title": "Remote Code Execution via Pickle Deserialization",
            "description": "Arbitrary code execution",
            "severity": "CRITICAL",
            "confidence": 0.60,
            "cwe": "CWE-502",
            "file_path": "main.py",
            "line_start": 4,
            "line_end": 4,
            "mantis_status": "VALID",
        }
    ]
    normalized_mantis = adapter.ingest_findings(mantis_findings_raw)
    mock_result = MantisExecutionResult(
        capability=AgentCapability.REVIEW,
        summary="Critical code review finding",
        analysis="Detailed RCE analysis",
        raw_findings=mantis_findings_raw,
        normalized_findings=normalized_mantis,
        metadata={"mantis_revision": "d13c93fb8e9779801711daea0d65fffa133c3b2d"},
        duration_seconds=1.2,
    )

    async def mock_run_command(argv, cwd=None, config=None):
        tool = argv[0]
        if "--version" in argv:
            return RunResult(return_code=0, stdout="1.0.0", stderr="")
        if tool == "semgrep":
            return RunResult(return_code=0, stdout='{"results": []}', stderr="")
        if tool == "pip-audit":
            return RunResult(return_code=0, stdout='{"dependencies": []}', stderr="")
        if tool == "trivy":
            return RunResult(return_code=0, stdout='{"Results": []}', stderr="")
        return RunResult(return_code=-1, stdout="", stderr="Unknown tool")

    with (
        patch("app.services.orchestrator.get_settings", return_value=settings),
        patch("app.services.mantis_advisory.get_settings", return_value=settings),
        patch("app.scanners.base.run_command", side_effect=mock_run_command),
        patch("app.scanners.semgrep.run_command", side_effect=mock_run_command),
        patch("app.scanners.pip_audit.run_command", side_effect=mock_run_command),
        patch("app.scanners.trivy.run_command", side_effect=mock_run_command),
        patch.object(MantisSafeRuntime, "check_availability", return_value=(True, "available")),
        patch.object(MantisSafeRuntime, "analyze", new_callable=AsyncMock, return_value=mock_result),
    ):
        await run_scan(scan.id, db_session)

    await db_session.refresh(scan)
    assert scan.status == ScanStatus.COMPLETED
    # Risk Gate MUST be PASS because deterministic scanners had 0 findings!
    assert scan.risk_gate == RiskGate.PASS

    # Mantis CRITICAL is persisted and visible
    all_findings = (
        await db_session.execute(
            select(Finding).where(Finding.scan_id == scan.id)
        )
    ).scalars().all()
    assert len(all_findings) == 1
    mantis_f = all_findings[0]
    assert mantis_f.scanner_name == "mantis"
    assert mantis_f.severity == Severity.CRITICAL
    assert mantis_f.correlation_group_id is None
    assert mantis_f.advisory is True
    assert mantis_f.risk_gate_eligible is False


@pytest.mark.asyncio
async def test_pipeline_isolation_high_review_plus_critical_mantis(
    db_session: AsyncSession, tmp_path: Path
):
    """Section 17:
    Deterministic scanner returns HIGH single-source with low confidence -> results in REVIEW.
    Mantis returns finding with same CWE, same file, same title, CRITICAL.
    Expected: Risk Gate remains REVIEW.
    Mantis does NOT corroborate, does NOT elevate evidence, does NOT elevate confidence,
    does NOT create correlation group with deterministic finding.
    """
    target = _create_sample_target(tmp_path)
    project = Project(name="Project Isolation 2")
    db_session.add(project)
    await db_session.flush()

    scan = Scan(
        project_id=project.id,
        source_path=str(target),
        scan_mode=ScanMode.SOURCE,
    )
    db_session.add(scan)
    await db_session.commit()

    settings = Settings(
        mantis_enabled=True,
        mantis_pipeline_enabled=True,
        mantis_execution_mode="read_only",
        allowed_workspace_root=tmp_path,
    )

    # Deterministic semgrep finding: HIGH, confidence 0.20 (single source -> REVIEW)
    semgrep_json = json.dumps({
        "results": [
            {
                "check_id": "python.lang.security.deserialization.pickle",
                "path": "main.py",
                "start": {"line": 4, "col": 12},
                "end": {"line": 4, "col": 30},
                "extra": {
                    "message": "Avoid using pickle for deserialization",
                    "severity": "ERROR",
                    "metadata": {
                        "cwe": ["CWE-502"],
                        "confidence": "LOW",
                    },
                },
            }
        ]
    })

    # Mantis finding: same file, same CWE, CRITICAL
    adapter = MantisAdapter()
    mantis_findings_raw = [
        {
            "id": "mantis-rce-1",
            "title": "Avoid using pickle for deserialization",
            "description": "Exploitable pickle deserialization leading to RCE",
            "severity": "CRITICAL",
            "confidence": 0.60,
            "cwe": "CWE-502",
            "file_path": "main.py",
            "line_start": 4,
            "line_end": 4,
            "mantis_status": "VALID",
        }
    ]
    normalized_mantis = adapter.ingest_findings(mantis_findings_raw)
    mock_result = MantisExecutionResult(
        capability=AgentCapability.REVIEW,
        summary="Critical code review finding",
        analysis="Pickle deserialization",
        raw_findings=mantis_findings_raw,
        normalized_findings=normalized_mantis,
        metadata={"mantis_revision": "d13c93fb8e9779801711daea0d65fffa133c3b2d"},
        duration_seconds=1.0,
    )

    async def mock_run_command(argv, cwd=None, config=None):
        tool = argv[0]
        if "--version" in argv:
            return RunResult(return_code=0, stdout="1.0.0", stderr="")
        if tool == "semgrep":
            return RunResult(return_code=0, stdout=semgrep_json, stderr="")
        if tool in ("pip-audit", "trivy"):
            return RunResult(return_code=0, stdout="{}", stderr="")
        return RunResult(return_code=-1, stdout="", stderr="Unknown tool")

    with (
        patch("app.services.orchestrator.get_settings", return_value=settings),
        patch("app.services.mantis_advisory.get_settings", return_value=settings),
        patch("app.scanners.base.run_command", side_effect=mock_run_command),
        patch("app.scanners.semgrep.run_command", side_effect=mock_run_command),
        patch("app.scanners.pip_audit.run_command", side_effect=mock_run_command),
        patch("app.scanners.trivy.run_command", side_effect=mock_run_command),
        patch.object(MantisSafeRuntime, "check_availability", return_value=(True, "available")),
        patch.object(MantisSafeRuntime, "analyze", new_callable=AsyncMock, return_value=mock_result),
    ):
        await run_scan(scan.id, db_session)

    await db_session.refresh(scan)
    assert scan.status == ScanStatus.COMPLETED
    # Risk Gate remains REVIEW (Mantis CRITICAL does NOT turn it into BLOCKED!)
    assert scan.risk_gate == RiskGate.REVIEW

    all_findings = (
        await db_session.execute(
            select(Finding).where(Finding.scan_id == scan.id).order_by(Finding.scanner_name)
        )
    ).scalars().all()
    assert len(all_findings) == 2

    mantis_f = next(f for f in all_findings if f.scanner_name == "mantis")
    semgrep_f = next(f for f in all_findings if f.scanner_name == "semgrep")

    # Mantis finding is standalone
    assert mantis_f.correlation_group_id is None
    assert mantis_f.evidence_level == EvidenceLevel.SINGLE_SOURCE

    # Semgrep finding is in its own correlation group, NOT corroborated by Mantis
    assert semgrep_f.correlation_group_id is not None
    assert semgrep_f.evidence_level == EvidenceLevel.SINGLE_SOURCE


@pytest.mark.asyncio
async def test_pipeline_structural_isolation_arguments(
    db_session: AsyncSession, tmp_path: Path
):
    """Section 47:
    Prove that arguments passed to compute_risk_gate(), correlate_findings(),
    and adjust_confidence() NEVER contain any finding with scanner_name == 'mantis'.
    """
    target = _create_sample_target(tmp_path)
    project = Project(name="Project Proof")
    db_session.add(project)
    await db_session.flush()

    scan = Scan(
        project_id=project.id,
        source_path=str(target),
        scan_mode=ScanMode.SOURCE,
    )
    db_session.add(scan)
    await db_session.commit()

    settings = Settings(
        mantis_enabled=True,
        mantis_pipeline_enabled=True,
        mantis_execution_mode="read_only",
        allowed_workspace_root=tmp_path,
    )

    semgrep_json = json.dumps({
        "results": [
            {
                "check_id": "test.rule",
                "path": "main.py",
                "start": {"line": 1, "col": 1},
                "end": {"line": 1, "col": 10},
                "extra": {"message": "test", "severity": "WARNING"},
            }
        ]
    })

    adapter = MantisAdapter()
    normalized_mantis = adapter.ingest_findings([
        {"title": "Mantis Finding", "severity": "CRITICAL", "file_path": "main.py"}
    ])
    mock_result = MantisExecutionResult(
        capability=AgentCapability.REVIEW,
        summary="Mantis result",
        analysis="Analysis",
        raw_findings=[],
        normalized_findings=normalized_mantis,
        metadata={"mantis_revision": "d13c93fb8e9779801711daea0d65fffa133c3b2d"},
        duration_seconds=1.0,
    )

    import app.services.orchestrator as orch
    real_compute_risk_gate = orch.compute_risk_gate
    real_correlate = orch.correlate_findings
    real_adjust_conf = orch.adjust_confidence
    real_dedup = orch.deduplicate_findings

    gate_findings_passed = []
    correlate_findings_passed = []
    adjust_findings_passed = []
    dedup_findings_passed = []

    def spy_risk_gate(findings):
        gate_findings_passed.extend(findings)
        return real_compute_risk_gate(findings)

    def spy_correlate(findings, scan_id):
        correlate_findings_passed.extend(findings)
        return real_correlate(findings, scan_id)

    def spy_adjust(findings):
        adjust_findings_passed.extend(findings)
        return real_adjust_conf(findings)

    def spy_dedup(findings):
        dedup_findings_passed.extend(findings)
        return real_dedup(findings)

    async def mock_run_command(argv, cwd=None, config=None):
        if "--version" in argv:
            return RunResult(return_code=0, stdout="1.0.0", stderr="")
        if argv[0] == "semgrep":
            return RunResult(return_code=0, stdout=semgrep_json, stderr="")
        return RunResult(return_code=0, stdout="{}", stderr="")

    with (
        patch("app.services.orchestrator.get_settings", return_value=settings),
        patch("app.services.mantis_advisory.get_settings", return_value=settings),
        patch("app.scanners.base.run_command", side_effect=mock_run_command),
        patch("app.scanners.semgrep.run_command", side_effect=mock_run_command),
        patch("app.scanners.pip_audit.run_command", side_effect=mock_run_command),
        patch("app.scanners.trivy.run_command", side_effect=mock_run_command),
        patch.object(orch, "compute_risk_gate", side_effect=spy_risk_gate),
        patch.object(orch, "correlate_findings", side_effect=spy_correlate),
        patch.object(orch, "adjust_confidence", side_effect=spy_adjust),
        patch.object(orch, "deduplicate_findings", side_effect=spy_dedup),
        patch.object(MantisSafeRuntime, "check_availability", return_value=(True, "available")),
        patch.object(MantisSafeRuntime, "analyze", new_callable=AsyncMock, return_value=mock_result),
    ):
        await run_scan(scan.id, db_session)

    # Assert deterministic findings entered the deterministic steps
    assert len(gate_findings_passed) > 0
    assert len(dedup_findings_passed) > 0
    assert len(correlate_findings_passed) > 0
    assert len(adjust_findings_passed) > 0

    # Invariant: NO mantis finding was in any deterministic gate/dedup/correlation input
    assert all(f.scanner_name != "mantis" for f in gate_findings_passed)
    assert all(f.scanner_name != "mantis" for f in dedup_findings_passed)
    assert all(f.scanner_name != "mantis" for f in correlate_findings_passed)
    assert all(f.scanner_name != "mantis" for f in adjust_findings_passed)


@pytest.mark.asyncio
async def test_pipeline_source_immutability(
    db_session: AsyncSession, tmp_path: Path
):
    """Section 37:
    Target workspace bytes before scan == bytes after scan.
    """
    target = _create_sample_target(tmp_path)
    project = Project(name="Project Immutability")
    db_session.add(project)
    await db_session.flush()

    scan = Scan(
        project_id=project.id,
        source_path=str(target),
        scan_mode=ScanMode.SOURCE,
    )
    db_session.add(scan)
    await db_session.commit()

    settings = Settings(
        mantis_enabled=True,
        mantis_pipeline_enabled=True,
        mantis_execution_mode="read_only",
        allowed_workspace_root=tmp_path,
    )

    hashes_before = _hash_tree(target)

    mock_result = MantisExecutionResult(
        capability=AgentCapability.REVIEW,
        summary="Clean review",
        analysis="Analysis",
        raw_findings=[],
        normalized_findings=[],
        metadata={"mantis_revision": "d13c93fb8e9779801711daea0d65fffa133c3b2d"},
        duration_seconds=0.5,
    )

    async def mock_run_command(argv, cwd=None, config=None):
        if "--version" in argv:
            return RunResult(return_code=0, stdout="1.0.0", stderr="")
        return RunResult(return_code=0, stdout="{}", stderr="")

    with (
        patch("app.services.orchestrator.get_settings", return_value=settings),
        patch("app.services.mantis_advisory.get_settings", return_value=settings),
        patch("app.scanners.base.run_command", side_effect=mock_run_command),
        patch("app.scanners.semgrep.run_command", side_effect=mock_run_command),
        patch("app.scanners.pip_audit.run_command", side_effect=mock_run_command),
        patch("app.scanners.trivy.run_command", side_effect=mock_run_command),
        patch.object(MantisSafeRuntime, "check_availability", return_value=(True, "available")),
        patch.object(MantisSafeRuntime, "analyze", new_callable=AsyncMock, return_value=mock_result),
    ):
        await run_scan(scan.id, db_session)

    hashes_after = _hash_tree(target)
    assert hashes_before == hashes_after


@pytest.mark.asyncio
async def test_scan_summary_actionable_count_excludes_mantis(client):
    """Section 31:
    Ensure actionable_count in scan summary does not count advisory Mantis findings.
    """
    # Create project and scan via API
    p_res = await client.post("/api/projects", json={"name": "Summary Project"})
    assert p_res.status_code == 201
    proj_id = p_res.json()["id"]

    # Direct DB injection for precise test setup
    from app.db.session import get_db

    # Query DB session from client override
    # We can create a scan directly through the client or route
    s_res = await client.post(
        "/api/scans",
        json={"project_id": proj_id, "source_path": None, "target_url": "http://localhost:8080", "scan_mode": "DAST_ONLY"},
    )
    assert s_res.status_code == 202
    scan_id = s_res.json()["id"]

    # Retrieve session to add findings
    # Use test client dependency override
    db_gen = client._transport.app.dependency_overrides[get_db]
    session_ctx = db_gen()
    db: AsyncSession = await session_ctx.__anext__()

    # 1 deterministic open finding
    f_det = Finding(
        scan_id=scan_id,
        scanner_name="semgrep",
        title="Deterministic Open Finding",
        raw_fingerprint="fp-det-1",
        normalized_fingerprint="nfp-det-1",
        severity=Severity.HIGH,
        status=FindingStatus.OPEN,
    )
    # 2 Mantis advisory findings
    f_mantis_1 = Finding(
        scan_id=scan_id,
        scanner_name="mantis",
        title="Mantis Finding 1",
        raw_fingerprint="fp-m-1",
        normalized_fingerprint="nfp-m-1",
        severity=Severity.CRITICAL,
        status=FindingStatus.OPEN,
    )
    f_mantis_2 = Finding(
        scan_id=scan_id,
        scanner_name="mantis",
        title="Mantis Finding 2",
        raw_fingerprint="fp-m-2",
        normalized_fingerprint="nfp-m-2",
        severity=Severity.HIGH,
        status=FindingStatus.OPEN,
    )
    f_fp = Finding(
        scan_id=scan_id,
        scanner_name="semgrep",
        title="FP Finding",
        raw_fingerprint="fp-fp",
        normalized_fingerprint="nfp-fp",
        severity=Severity.HIGH,
        status=FindingStatus.FALSE_POSITIVE,
    )
    f_ar = Finding(
        scan_id=scan_id,
        scanner_name="semgrep",
        title="AR Finding",
        raw_fingerprint="fp-ar",
        normalized_fingerprint="nfp-ar",
        severity=Severity.HIGH,
        status=FindingStatus.ACCEPTED_RISK,
    )
    f_abd = Finding(
        scan_id=scan_id,
        scanner_name="semgrep",
        title="ABD Finding",
        raw_fingerprint="fp-abd",
        normalized_fingerprint="nfp-abd",
        severity=Severity.HIGH,
        status=FindingStatus.ACCEPTED_BY_DESIGN,
    )
    f_fixed = Finding(
        scan_id=scan_id,
        scanner_name="semgrep",
        title="Fixed Finding",
        raw_fingerprint="fp-fixed",
        normalized_fingerprint="nfp-fixed",
        severity=Severity.HIGH,
        status=FindingStatus.FIXED,
    )
    db.add_all([f_det, f_mantis_1, f_mantis_2, f_fp, f_ar, f_abd, f_fixed])
    await db.commit()

    sum_res = await client.get(f"/api/scans/{scan_id}/summary")
    assert sum_res.status_code == 200
    data = sum_res.json()

    # Actionable count must ONLY count deterministic open findings
    assert data["actionable_count"] == 1
    assert data["false_positive_count"] == 1
    assert data["accepted_risk_count"] == 1
    assert data["accepted_by_design_count"] == 1
    assert data["fixed_count"] == 1
    # Totals count all findings in database
    assert data["totals"]["critical"] == 1
    assert data["totals"]["high"] == 6


def test_finding_risk_gate_eligible_semantics() -> None:
    """Test risk_gate_eligible property strictly reflects open deterministic findings."""
    f_det_open = Finding(
        scan_id="s1",
        scanner_name="semgrep",
        raw_fingerprint="fp1",
        normalized_fingerprint="nfp1",
        status=FindingStatus.OPEN,
    )
    assert f_det_open.risk_gate_eligible is True

    f_mantis_open = Finding(
        scan_id="s1",
        scanner_name="mantis",
        raw_fingerprint="fp2",
        normalized_fingerprint="nfp2",
        status=FindingStatus.OPEN,
    )
    assert f_mantis_open.risk_gate_eligible is False

    for non_open_status in [
        FindingStatus.FALSE_POSITIVE,
        FindingStatus.ACCEPTED_RISK,
        FindingStatus.ACCEPTED_BY_DESIGN,
        FindingStatus.FIXED,
    ]:
        f_det_non_open = Finding(
            scan_id="s1",
            scanner_name="semgrep",
            raw_fingerprint=f"fp-{non_open_status.value}",
            normalized_fingerprint=f"nfp-{non_open_status.value}",
            status=non_open_status,
        )
        assert f_det_non_open.risk_gate_eligible is False, f"Expected False for {non_open_status}"


@pytest.mark.asyncio
async def test_pipeline_check_availability_exception_audited(
    db_session: AsyncSession, tmp_path: Path
) -> None:
    """Requirement: runtime check_availability exception handled fail-open and audited without leaking secrets."""
    target = _create_sample_target(tmp_path)
    project = Project(name="Project Check Availability Throw")
    db_session.add(project)
    await db_session.flush()

    scan = Scan(
        project_id=project.id,
        source_path=str(target),
        scan_mode=ScanMode.SOURCE,
    )
    db_session.add(scan)
    await db_session.commit()

    settings = Settings(
        mantis_enabled=True,
        mantis_pipeline_enabled=True,
        mantis_execution_mode="read_only",
        allowed_workspace_root=tmp_path,
    )

    async def mock_run_command(argv, cwd=None, config=None):
        if "--version" in argv:
            return RunResult(return_code=0, stdout="1.0.0", stderr="")
        return RunResult(return_code=0, stdout="{}", stderr="")

    secret_raw = "sk-live-secret-key-1234567890"
    secret_in_exception = f"api_key='{secret_raw}'"
    analyze_mock = AsyncMock()

    with (
        patch("app.services.orchestrator.get_settings", return_value=settings),
        patch("app.services.mantis_advisory.get_settings", return_value=settings),
        patch("app.scanners.base.run_command", side_effect=mock_run_command),
        patch("app.scanners.semgrep.run_command", side_effect=mock_run_command),
        patch("app.scanners.pip_audit.run_command", side_effect=mock_run_command),
        patch("app.scanners.trivy.run_command", side_effect=mock_run_command),
        patch.object(
            MantisSafeRuntime,
            "check_availability",
            side_effect=RuntimeError(f"Availability check crash: {secret_in_exception}"),
        ),
        patch.object(MantisSafeRuntime, "analyze", new_callable=AsyncMock, side_effect=analyze_mock),
    ):
        await run_scan(scan.id, db_session)

    await db_session.refresh(scan)
    assert scan.status == ScanStatus.COMPLETED
    assert scan.risk_gate == RiskGate.PASS
    assert analyze_mock.called is False

    runs = (
        await db_session.execute(
            select(ScannerRun).where(
                ScannerRun.scan_id == scan.id,
                ScannerRun.scanner_name == "mantis-advisory-review",
            )
        )
    ).scalars().all()

    assert len(runs) == 1
    run = runs[0]
    assert run.status in (ScannerRunStatus.FAILED, ScannerRunStatus.UNAVAILABLE)
    assert secret_raw not in (run.error_message or "")
    assert secret_raw not in (run.raw_output or "")
    raw_meta = json.loads(run.raw_output)
    assert raw_meta["advisory"] is True
    assert raw_meta["risk_gate_eligible"] is False
    assert raw_meta["error_class"] == "RuntimeError"


async def test_mantis_advisory_generates_corroboration_candidates(
    db_session: AsyncSession, tmp_path: Path
) -> None:
    """Verify MantisAdvisoryResult produces typed corroboration candidates."""
    proj_dir = tmp_path / "cand_project"
    proj_dir.mkdir()
    (proj_dir / "main.py").write_text("print('hello')")

    project = Project(name="Cand Project")
    db_session.add(project)
    await db_session.flush()

    scan = Scan(project_id=project.id, source_path=str(proj_dir))
    db_session.add(scan)
    await db_session.commit()

    settings = Settings(
        mantis_enabled=True,
        mantis_pipeline_enabled=True,
        mantis_execution_mode="read_only",
        mantis_root=tmp_path,
        mantis_revision="d13c93fb8e9779801711daea0d65fffa133c3b2d",
        mantis_base_url="https://api.openai.com/v1",
        mantis_api_key="test-key",
    )

    norm = NormalizedFinding(
        title="XSS",
        description="Cross site scripting",
        severity=Severity.HIGH,
        confidence=0.55,
        scanner_name="mantis",
        cwe="CWE-79",
        file_path="main.py",
        line_start=10,
        raw_fingerprint="fp1",
        normalized_fingerprint="nfp1",
        raw_data={"mantis_status": "VALID", "mantis_status_explicit": True},
    )
    exec_res = MantisExecutionResult(
        capability=AgentCapability.REVIEW,
        summary="ok",
        analysis="details",
        raw_findings=[{}],
        normalized_findings=[norm],
        duration_seconds=1.0,
    )

    with (
        patch.object(MantisSafeRuntime, "check_availability", return_value=(True, "")),
        patch.object(MantisSafeRuntime, "analyze", new_callable=AsyncMock, return_value=exec_res),
    ):
        res = await run_mantis_advisory_analysis(
            scan=scan,
            project_path=proj_dir,
            session=db_session,
            settings=settings,
        )

    assert res.attempted is True
    assert res.available is True
    assert len(res.corroboration_candidates) == 1
    cand = res.corroboration_candidates[0]
    assert cand.cwe == "CWE-79"
    assert cand.file_path == "main.py"
    assert cand.line_start == 10
    assert cand.confidence == 0.55
    assert cand.mantis_status == "VALID"
    assert cand.mantis_status_explicit is True
    assert cand.source_revision == settings.mantis_revision
