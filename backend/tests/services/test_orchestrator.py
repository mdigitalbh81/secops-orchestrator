"""Tests for scan orchestrator service."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

import app.services.orchestrator
from app.agents.base import AgentCapability
from app.agents.mantis import MantisAdapter
from app.agents.mantis_runtime import MantisExecutionResult, MantisSafeRuntime
from app.core.config import Settings
from app.models.correlation import CorrelationGroup
from app.models.disposition import FindingDisposition
from app.models.enums import (
    EvidenceLevel,
    FindingStatus,
    RiskGate,
    ScannerRunStatus,
    ScanStatus,
    Severity,
)
from app.models.finding import Finding, FindingEvidence
from app.models.project import Project
from app.models.scan import Scan
from app.models.scanner_run import ScannerRun
from app.security.runner import RunResult
from app.services.agentic_corroboration import POLICY_VERSION
from app.services.orchestrator import run_scan


async def test_orchestrator_full_flow(
    db_session: AsyncSession,
    tmp_path: Path,
    semgrep_json: str,
    npm_audit_json: str,
):
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

    await db_session.refresh(scan)
    assert scan.status == ScanStatus.COMPLETED
    assert scan.risk_gate == RiskGate.BLOCKED

    runs = (
        (await db_session.execute(select(ScannerRun).where(ScannerRun.scan_id == scan.id)))
        .scalars()
        .all()
    )
    statuses = {r.scanner_name: r.status for r in runs}
    assert statuses["semgrep"] == ScannerRunStatus.COMPLETED
    assert statuses["npm-audit"] == ScannerRunStatus.COMPLETED
    assert statuses["pip-audit"] == ScannerRunStatus.NOT_APPLICABLE
    assert statuses["trivy"] == ScannerRunStatus.COMPLETED

    findings = (
        (await db_session.execute(select(Finding).where(Finding.scan_id == scan.id)))
        .scalars()
        .all()
    )
    assert len(findings) > 0

    npm_run = next(r for r in runs if r.scanner_name == "npm-audit")
    raw_data = json.loads(npm_run.raw_output)
    assert "subtargets" in raw_data
    assert len(raw_data["subtargets"]) == 1
    assert raw_data["subtargets"][0]["status"] == "COMPLETED"
    assert raw_data["subtargets"][0]["stdout"] != ""


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


async def test_partial_failure_two_targets_success_completed(
    db_session: AsyncSession,
    tmp_path: Path,
    npm_audit_json: str,
):
    """2 targets both succeed -> COMPLETED."""
    proj_dir = tmp_path / "multi_npm_ok"
    proj_dir.mkdir()
    (proj_dir / "frontend").mkdir()
    (proj_dir / "frontend" / "package.json").write_text('{"name": "frontend"}')
    (proj_dir / "admin").mkdir()
    (proj_dir / "admin" / "package.json").write_text('{"name": "admin"}')

    project = Project(name="Multi OK")
    db_session.add(project)
    await db_session.flush()

    scan = Scan(project_id=project.id, source_path=str(proj_dir))
    db_session.add(scan)
    await db_session.commit()

    async def mock_run_command(argv, cwd=None, config=None):
        tool = argv[0]
        if tool == "npm":
            if "--version" in argv:
                return RunResult(return_code=0, stdout="10.0.0", stderr="")
            return RunResult(return_code=1, stdout=npm_audit_json, stderr="")
        if "--version" in argv:
            return RunResult(return_code=0, stdout="1.0.0", stderr="")
        return RunResult(return_code=0, stdout="{}", stderr="")

    with (
        patch("app.scanners.base.run_command", side_effect=mock_run_command),
        patch("app.scanners.semgrep.run_command", side_effect=mock_run_command),
        patch("app.scanners.npm_audit.run_command", side_effect=mock_run_command),
        patch("app.scanners.pip_audit.run_command", side_effect=mock_run_command),
        patch("app.scanners.trivy.run_command", side_effect=mock_run_command),
    ):
        await run_scan(scan.id, db_session)

    runs = (
        (await db_session.execute(select(ScannerRun).where(ScannerRun.scan_id == scan.id)))
        .scalars()
        .all()
    )
    npm_run = next(r for r in runs if r.scanner_name == "npm-audit")
    assert npm_run.status == ScannerRunStatus.COMPLETED
    raw = json.loads(npm_run.raw_output)
    assert len(raw["subtargets"]) == 2
    assert all(st["status"] == "COMPLETED" for st in raw["subtargets"])


async def test_partial_failure_two_targets_failure_failed(
    db_session: AsyncSession,
    tmp_path: Path,
):
    """2 targets both fail -> FAILED."""
    proj_dir = tmp_path / "multi_npm_fail"
    proj_dir.mkdir()
    (proj_dir / "frontend").mkdir()
    (proj_dir / "frontend" / "package.json").write_text('{"name": "frontend"}')
    (proj_dir / "admin").mkdir()
    (proj_dir / "admin" / "package.json").write_text('{"name": "admin"}')

    project = Project(name="Multi Fail")
    db_session.add(project)
    await db_session.flush()

    scan = Scan(project_id=project.id, source_path=str(proj_dir))
    db_session.add(scan)
    await db_session.commit()

    async def mock_run_command(argv, cwd=None, config=None):
        tool = argv[0]
        if tool == "npm":
            if "--version" in argv:
                return RunResult(return_code=0, stdout="10.0.0", stderr="")
            return RunResult(return_code=-1, stdout="", stderr="npm ERR! registry down")
        if "--version" in argv:
            return RunResult(return_code=0, stdout="1.0.0", stderr="")
        return RunResult(return_code=0, stdout="{}", stderr="")

    with (
        patch("app.scanners.base.run_command", side_effect=mock_run_command),
        patch("app.scanners.semgrep.run_command", side_effect=mock_run_command),
        patch("app.scanners.npm_audit.run_command", side_effect=mock_run_command),
        patch("app.scanners.pip_audit.run_command", side_effect=mock_run_command),
        patch("app.scanners.trivy.run_command", side_effect=mock_run_command),
    ):
        await run_scan(scan.id, db_session)

    runs = (
        (await db_session.execute(select(ScannerRun).where(ScannerRun.scan_id == scan.id)))
        .scalars()
        .all()
    )
    npm_run = next(r for r in runs if r.scanner_name == "npm-audit")
    assert npm_run.status == ScannerRunStatus.FAILED
    raw = json.loads(npm_run.raw_output)
    assert len(raw["subtargets"]) == 2
    assert all(st["status"] == "FAILED" for st in raw["subtargets"])


async def test_partial_failure_one_success_one_failure_partial(
    db_session: AsyncSession,
    tmp_path: Path,
    npm_audit_json: str,
):
    """1 success, 1 failure -> PARTIAL."""
    proj_dir = tmp_path / "multi_npm_partial"
    proj_dir.mkdir()
    (proj_dir / "frontend").mkdir()
    (proj_dir / "frontend" / "package.json").write_text('{"name": "frontend"}')
    (proj_dir / "admin").mkdir()
    (proj_dir / "admin" / "package.json").write_text('{"name": "admin"}')

    project = Project(name="Multi Partial")
    db_session.add(project)
    await db_session.flush()

    scan = Scan(project_id=project.id, source_path=str(proj_dir))
    db_session.add(scan)
    await db_session.commit()

    async def mock_run_command(argv, cwd=None, config=None):
        tool = argv[0]
        if tool == "npm":
            if "--version" in argv:
                return RunResult(return_code=0, stdout="10.0.0", stderr="")
            if cwd and "frontend" in str(cwd):
                return RunResult(return_code=1, stdout=npm_audit_json, stderr="")
            else:
                return RunResult(return_code=-1, stdout="", stderr="fatal package lock error")
        if "--version" in argv:
            return RunResult(return_code=0, stdout="1.0.0", stderr="")
        return RunResult(return_code=0, stdout="{}", stderr="")

    with (
        patch("app.scanners.base.run_command", side_effect=mock_run_command),
        patch("app.scanners.semgrep.run_command", side_effect=mock_run_command),
        patch("app.scanners.npm_audit.run_command", side_effect=mock_run_command),
        patch("app.scanners.pip_audit.run_command", side_effect=mock_run_command),
        patch("app.scanners.trivy.run_command", side_effect=mock_run_command),
    ):
        await run_scan(scan.id, db_session)

    runs = (
        (await db_session.execute(select(ScannerRun).where(ScannerRun.scan_id == scan.id)))
        .scalars()
        .all()
    )
    npm_run = next(r for r in runs if r.scanner_name == "npm-audit")
    assert npm_run.status == ScannerRunStatus.PARTIAL
    assert "1 of 2 target(s) failed" in (npm_run.error_message or "")
    raw = json.loads(npm_run.raw_output)
    statuses = {st["subproject"]: st["status"] for st in raw["subtargets"]}
    assert statuses["frontend"] == "COMPLETED"
    assert statuses["admin"] == "FAILED"


async def test_partial_failure_one_success_one_timeout_partial(
    db_session: AsyncSession,
    tmp_path: Path,
    npm_audit_json: str,
):
    """1 success, 1 timeout -> PARTIAL."""
    proj_dir = tmp_path / "multi_npm_timeout"
    proj_dir.mkdir()
    (proj_dir / "frontend").mkdir()
    (proj_dir / "frontend" / "package.json").write_text('{"name": "frontend"}')
    (proj_dir / "admin").mkdir()
    (proj_dir / "admin" / "package.json").write_text('{"name": "admin"}')

    project = Project(name="Multi Timeout")
    db_session.add(project)
    await db_session.flush()

    scan = Scan(project_id=project.id, source_path=str(proj_dir))
    db_session.add(scan)
    await db_session.commit()

    async def mock_run_command(argv, cwd=None, config=None):
        tool = argv[0]
        if tool == "npm":
            if "--version" in argv:
                return RunResult(return_code=0, stdout="10.0.0", stderr="")
            if cwd and "frontend" in str(cwd):
                return RunResult(return_code=1, stdout=npm_audit_json, stderr="")
            else:
                return RunResult(return_code=-1, stdout="", stderr="Timed out", timed_out=True)
        if "--version" in argv:
            return RunResult(return_code=0, stdout="1.0.0", stderr="")
        return RunResult(return_code=0, stdout="{}", stderr="")

    with (
        patch("app.scanners.base.run_command", side_effect=mock_run_command),
        patch("app.scanners.semgrep.run_command", side_effect=mock_run_command),
        patch("app.scanners.npm_audit.run_command", side_effect=mock_run_command),
        patch("app.scanners.pip_audit.run_command", side_effect=mock_run_command),
        patch("app.scanners.trivy.run_command", side_effect=mock_run_command),
    ):
        await run_scan(scan.id, db_session)

    runs = (
        (await db_session.execute(select(ScannerRun).where(ScannerRun.scan_id == scan.id)))
        .scalars()
        .all()
    )
    npm_run = next(r for r in runs if r.scanner_name == "npm-audit")
    assert npm_run.status == ScannerRunStatus.PARTIAL
    raw = json.loads(npm_run.raw_output)
    statuses = {st["subproject"]: st["status"] for st in raw["subtargets"]}
    assert statuses["frontend"] == "COMPLETED"
    assert statuses["admin"] == "TIMED_OUT"


async def test_subproject_provenance_in_finding_evidence(
    db_session: AsyncSession,
    tmp_path: Path,
    npm_audit_json: str,
    pip_audit_json: str,
):
    """Verify finding evidence carries subproject and manifest metadata."""
    proj_dir = tmp_path / "monorepo_prov"
    proj_dir.mkdir()
    (proj_dir / "frontend").mkdir()
    (proj_dir / "frontend" / "package.json").write_text('{"name": "frontend"}')
    (proj_dir / "backend").mkdir()
    (proj_dir / "backend" / "requirements.txt").write_text("flask==2.3.0")

    project = Project(name="Provenance Project")
    db_session.add(project)
    await db_session.flush()

    scan = Scan(project_id=project.id, source_path=str(proj_dir))
    db_session.add(scan)
    await db_session.commit()

    async def mock_run_command(argv, cwd=None, config=None):
        tool = argv[0]
        if tool == "npm":
            if "--version" in argv:
                return RunResult(return_code=0, stdout="10.0.0", stderr="")
            return RunResult(return_code=1, stdout=npm_audit_json, stderr="")
        elif tool == "pip-audit":
            if "--version" in argv:
                return RunResult(return_code=0, stdout="1.0.0", stderr="")
            return RunResult(return_code=1, stdout=pip_audit_json, stderr="")
        if "--version" in argv:
            return RunResult(return_code=0, stdout="1.0.0", stderr="")
        return RunResult(return_code=0, stdout="{}", stderr="")

    with (
        patch("app.scanners.base.run_command", side_effect=mock_run_command),
        patch("app.scanners.semgrep.run_command", side_effect=mock_run_command),
        patch("app.scanners.npm_audit.run_command", side_effect=mock_run_command),
        patch("app.scanners.pip_audit.run_command", side_effect=mock_run_command),
        patch("app.scanners.trivy.run_command", side_effect=mock_run_command),
    ):
        await run_scan(scan.id, db_session)

    # Query evidences
    evidences = (await db_session.execute(select(FindingEvidence))).scalars().all()
    assert len(evidences) > 0

    npm_evidences = [e for e in evidences if e.scanner_name == "npm-audit"]
    assert len(npm_evidences) > 0
    for ev in npm_evidences:
        assert ev.raw_data is not None
        assert ev.raw_data.get("subproject") == "frontend"
        assert ev.raw_data.get("manifest") == "frontend/package.json"

    pip_evidences = [e for e in evidences if e.scanner_name == "pip-audit"]
    assert len(pip_evidences) > 0
    for ev in pip_evidences:
        assert ev.raw_data is not None
        assert ev.raw_data.get("subproject") == "backend"
        assert ev.raw_data.get("manifest") == "backend/requirements.txt"


async def test_scanner_execution_count_exact(
    db_session: AsyncSession,
    tmp_path: Path,
    npm_audit_json: str,
):
    """Verify each target is executed exactly once per scan."""
    proj_dir = tmp_path / "monorepo_count"
    proj_dir.mkdir()
    (proj_dir / "frontend").mkdir()
    (proj_dir / "frontend" / "package.json").write_text('{"name": "frontend"}')
    (proj_dir / "admin").mkdir()
    (proj_dir / "admin" / "package.json").write_text('{"name": "admin"}')

    project = Project(name="Execution Count Project")
    db_session.add(project)
    await db_session.flush()

    scan = Scan(project_id=project.id, source_path=str(proj_dir))
    db_session.add(scan)
    await db_session.commit()

    npm_scan_calls = []

    async def mock_run_command(argv, cwd=None, config=None):
        tool = argv[0]
        if tool == "npm":
            if "--version" in argv:
                return RunResult(return_code=0, stdout="10.0.0", stderr="")
            npm_scan_calls.append(cwd)
            return RunResult(return_code=1, stdout=npm_audit_json, stderr="")
        if "--version" in argv:
            return RunResult(return_code=0, stdout="1.0.0", stderr="")
        return RunResult(return_code=0, stdout="{}", stderr="")

    with (
        patch("app.scanners.base.run_command", side_effect=mock_run_command),
        patch("app.scanners.semgrep.run_command", side_effect=mock_run_command),
        patch("app.scanners.npm_audit.run_command", side_effect=mock_run_command),
        patch("app.scanners.pip_audit.run_command", side_effect=mock_run_command),
        patch("app.scanners.trivy.run_command", side_effect=mock_run_command),
    ):
        await run_scan(scan.id, db_session)

    # 2 npm targets -> exactly 2 scan executions
    assert len(npm_scan_calls) == 2
    cwds = {str(c) for c in npm_scan_calls}
    assert str(proj_dir / "frontend") in cwds
    assert str(proj_dir / "admin") in cwds


async def test_raw_output_preservation_and_secret_redaction(
    db_session: AsyncSession,
    tmp_path: Path,
):
    """Verify raw output preservation and secret redaction in ScannerRun.raw_output."""
    proj_dir = tmp_path / "secrets_project"
    proj_dir.mkdir()
    (proj_dir / "package.json").write_text('{"name": "secrets-app"}')

    project = Project(name="Secrets Project")
    db_session.add(project)
    await db_session.flush()

    scan = Scan(project_id=project.id, source_path=str(proj_dir))
    db_session.add(scan)
    await db_session.commit()

    sensitive_stdout = json.dumps(
        {
            "vulnerabilities": {
                "bad-pkg": {
                    "name": "bad-pkg",
                    "severity": "high",
                    "title": "Leaked AWS: AKIAIOSFODNN7EXAMPLE and api_key='sk_live_1234567890abcdef'",
                    "via": [{"cve": "CVE-2023-9999", "title": "secret leak"}],
                }
            }
        }
    )

    async def mock_run_command(argv, cwd=None, config=None):
        tool = argv[0]
        if tool == "npm":
            if "--version" in argv:
                return RunResult(return_code=0, stdout="10.0.0", stderr="")
            return RunResult(
                return_code=1,
                stdout=sensitive_stdout,
                stderr="Error with secret: AKIAIOSFODNN7EXAMPLE",
            )
        if "--version" in argv:
            return RunResult(return_code=0, stdout="1.0.0", stderr="")
        return RunResult(return_code=0, stdout="{}", stderr="")

    with (
        patch("app.scanners.base.run_command", side_effect=mock_run_command),
        patch("app.scanners.semgrep.run_command", side_effect=mock_run_command),
        patch("app.scanners.npm_audit.run_command", side_effect=mock_run_command),
        patch("app.scanners.pip_audit.run_command", side_effect=mock_run_command),
        patch("app.scanners.trivy.run_command", side_effect=mock_run_command),
    ):
        await run_scan(scan.id, db_session)

    runs = (
        (await db_session.execute(select(ScannerRun).where(ScannerRun.scan_id == scan.id)))
        .scalars()
        .all()
    )
    npm_run = next(r for r in runs if r.scanner_name == "npm-audit")
    raw = json.loads(npm_run.raw_output)
    subtarget = raw["subtargets"][0]

    assert subtarget["status"] == "COMPLETED"
    assert "[REDACTED_SECRET]" in subtarget["stdout"]
    assert "AKIAIOSFODNN7EXAMPLE" not in subtarget["stdout"]
    assert "[REDACTED_SECRET]" in subtarget["stderr"]
    assert "AKIAIOSFODNN7EXAMPLE" not in subtarget["stderr"]


async def test_successful_scan_with_zero_findings_completes_with_pass(
    db_session: AsyncSession,
    tmp_path: Path,
) -> None:
    """Zero findings scan must complete with COMPLETED status and PASS risk gate."""
    proj_dir = tmp_path / "clean_project"
    proj_dir.mkdir()
    (proj_dir / "package.json").write_text('{"name": "clean-app"}')

    project = Project(name="Clean Project")
    db_session.add(project)
    await db_session.flush()

    scan = Scan(project_id=project.id, source_path=str(proj_dir))
    db_session.add(scan)
    await db_session.commit()

    async def mock_run_command(argv, cwd=None, config=None):
        tool = argv[0]
        if tool == "npm":
            if "--version" in argv:
                return RunResult(return_code=0, stdout="10.0.0", stderr="")
            return RunResult(
                return_code=0,
                stdout=json.dumps({"vulnerabilities": {}}),
                stderr="",
            )
        if "--version" in argv:
            return RunResult(return_code=0, stdout="1.0.0", stderr="")
        return RunResult(return_code=0, stdout="{}", stderr="")

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
    assert scan.risk_gate == RiskGate.PASS
    assert scan.completed_at is not None

    findings = (
        (await db_session.execute(select(Finding).where(Finding.scan_id == scan.id)))
        .scalars()
        .all()
    )
    assert len(findings) == 0

    groups = (
        (
            await db_session.execute(
                select(CorrelationGroup).where(CorrelationGroup.scan_id == scan.id)
            )
        )
        .scalars()
        .all()
    )
    assert len(groups) == 0

    runs = (
        (await db_session.execute(select(ScannerRun).where(ScannerRun.scan_id == scan.id)))
        .scalars()
        .all()
    )
    statuses = {r.scanner_name: r.status for r in runs}
    assert statuses.get("npm-audit") == ScannerRunStatus.COMPLETED


async def test_orchestrator_mantis_corroboration_positive_flow(
    db_session: AsyncSession,
    tmp_path: Path,
) -> None:
    """Section 60: Prove positive Mantis corroboration flow end-to-end.

    Semgrep HIGH 0.55 CWE-79 + Mantis VALID 0.55 CWE-79 within 5 lines
    -> Semgrep promoted to CORROBORATED_STATIC -> Risk Gate BLOCKED.
    Mantis remains SINGLE_SOURCE advisory.
    Mantis never appears in compute_risk_gate(), dedup, correlation, or adjust_confidence.
    """
    proj_dir = tmp_path / "corrob_project"
    proj_dir.mkdir()
    (proj_dir / "app").mkdir()
    (proj_dir / "app" / "views.py").write_text("def render_user(req):\n    return req.name\n")

    project = Project(name="Corrob Project")
    db_session.add(project)
    await db_session.flush()

    scan = Scan(project_id=project.id, source_path=str(proj_dir))
    db_session.add(scan)
    await db_session.commit()

    semgrep_output = json.dumps({
        "results": [
            {
                "check_id": "rules.views.xss",
                "path": "app/views.py",
                "start": {"line": 100, "col": 5},
                "end": {"line": 100, "col": 20},
                "extra": {
                    "message": "Reflected XSS in view",
                    "severity": "ERROR",
                    "metadata": {"cwe": ["CWE-79"]},
                },
            }
        ]
    })

    mantis_raw = [
        {
            "id": "mantis-xss-100",
            "title": "Reflected XSS in render_user",
            "description": "User input directly rendered",
            "severity": "HIGH",
            "confidence": 0.55,
            "cwe": "CWE-79",
            "file_path": "app/views.py",
            "line_start": 103,
            "line_end": 103,
            "mantis_status": "VALID",
        }
    ]
    adapter = MantisAdapter()
    norm_mantis = adapter.ingest_findings(mantis_raw)
    mock_mantis_res = MantisExecutionResult(
        capability=AgentCapability.REVIEW,
        summary="Found valid XSS matching view",
        analysis="Detailed XSS analysis",
        raw_findings=mantis_raw,
        normalized_findings=norm_mantis,
        metadata={"mantis_revision": "d13c93fb8e9779801711daea0d65fffa133c3b2d"},
        duration_seconds=1.2,
    )

    settings = Settings(
        mantis_enabled=True,
        mantis_pipeline_enabled=True,
        mantis_gate_corroboration_enabled=True,
       mantis_execution_mode="read_only",
       mantis_root=tmp_path,
        allowed_workspace_root=tmp_path,
       mantis_revision="d13c93fb8e9779801711daea0d65fffa133c3b2d",
        mantis_base_url="https://api.openai.com/v1",
        mantis_api_key="test-key",
    )

    async def mock_run_command(argv, cwd=None, config=None):
        tool = argv[0]
        if "--version" in argv:
            return RunResult(return_code=0, stdout="1.0.0", stderr="")
        if tool == "semgrep":
            return RunResult(return_code=0, stdout=semgrep_output, stderr="")
        if tool in ("pip-audit", "trivy", "npm"):
            return RunResult(return_code=0, stdout="{}", stderr="")
        return RunResult(return_code=-1, stdout="", stderr="Unknown tool")

    # Spies for architectural isolation checks
    risk_gate_inputs: list[list] = []
    orig_compute_risk_gate = app.services.orchestrator.compute_risk_gate

    def spy_risk_gate(findings):
        risk_gate_inputs.append(list(findings))
        return orig_compute_risk_gate(findings)

    dedup_inputs: list[list] = []
    orig_dedup = app.services.orchestrator.deduplicate_findings

    def spy_dedup(findings):
        dedup_inputs.append(list(findings))
        return orig_dedup(findings)

    correlate_inputs: list[list] = []
    orig_correlate = app.services.orchestrator.correlate_findings

    def spy_correlate(findings, s_id):
        correlate_inputs.append(list(findings))
        return orig_correlate(findings, s_id)

    adjust_conf_inputs: list[list] = []
    orig_adjust_conf = app.services.orchestrator.adjust_confidence

    def spy_adjust_conf(findings):
        adjust_conf_inputs.append(list(findings))
        return orig_adjust_conf(findings)

    with (
        patch("app.services.orchestrator.get_settings", return_value=settings),
        patch("app.services.mantis_advisory.get_settings", return_value=settings),
        patch("app.scanners.base.run_command", side_effect=mock_run_command),
        patch("app.scanners.semgrep.run_command", side_effect=mock_run_command),
        patch("app.scanners.pip_audit.run_command", side_effect=mock_run_command),
        patch("app.scanners.trivy.run_command", side_effect=mock_run_command),
        patch.object(MantisSafeRuntime, "check_availability", return_value=(True, "available")),
        patch.object(MantisSafeRuntime, "analyze", new_callable=AsyncMock, return_value=mock_mantis_res),
        patch("app.services.orchestrator.compute_risk_gate", side_effect=spy_risk_gate),
        patch("app.services.orchestrator.deduplicate_findings", side_effect=spy_dedup),
        patch("app.services.orchestrator.correlate_findings", side_effect=spy_correlate),
        patch("app.services.orchestrator.adjust_confidence", side_effect=spy_adjust_conf),
    ):
        await run_scan(scan.id, db_session)

    await db_session.refresh(scan)
    assert scan.status == ScanStatus.COMPLETED
    assert scan.risk_gate == RiskGate.BLOCKED

    # Query DB findings
    findings = (
        await db_session.execute(select(Finding).where(Finding.scan_id == scan.id))
    ).scalars().all()

    semgrep_f = next(f for f in findings if f.scanner_name == "semgrep")
    mantis_f = next(f for f in findings if f.scanner_name == "mantis")

    # Deterministic Semgrep promoted to CORROBORATED_STATIC
    assert semgrep_f.evidence_level == EvidenceLevel.CORROBORATED_STATIC
    assert semgrep_f.severity == Severity.HIGH
    assert semgrep_f.confidence == 0.50  # No confidence boost applied!
    assert semgrep_f.risk_gate_eligible is True
    assert semgrep_f.advisory is False

    # Mantis remains SINGLE_SOURCE and advisory
    assert mantis_f.evidence_level == EvidenceLevel.SINGLE_SOURCE
    assert mantis_f.risk_gate_eligible is False
    assert mantis_f.advisory is True
    assert mantis_f.correlation_group_id is None

    # Correlation group synchronized to CORROBORATED_STATIC
    cg = (
        await db_session.execute(select(CorrelationGroup).where(CorrelationGroup.scan_id == scan.id))
    ).scalar_one()
    assert cg.evidence_level == EvidenceLevel.CORROBORATED_STATIC
    assert cg.severity == Severity.HIGH
    assert cg.confidence == 0.50

    # Semgrep finding has FindingEvidence from Mantis
    evidences = (
        await db_session.execute(select(FindingEvidence).where(FindingEvidence.finding_id == semgrep_f.id))
    ).scalars().all()
    mantis_ev = next(e for e in evidences if e.scanner_name == "mantis")
    assert mantis_ev.raw_data["policy_version"] == POLICY_VERSION
    assert mantis_ev.raw_data["match_rule"] == "cwe_file_line"
    assert mantis_ev.raw_data["line_distance"] == 3
    assert mantis_ev.raw_data["promotion_to"] == "CORROBORATED_STATIC"

    # Section 38 Spy: compute_risk_gate input checks
    assert len(risk_gate_inputs) == 1
    gate_findings = risk_gate_inputs[0]
    assert all(f.scanner_name != "mantis" for f in gate_findings)
    gate_semgrep = next(f for f in gate_findings if f.scanner_name == "semgrep")
    assert gate_semgrep.evidence_level == EvidenceLevel.CORROBORATED_STATIC

    # Section 39 Spy: Mantis never appeared in dedup, correlation, or confidence
    assert len(dedup_inputs) == 1
    assert all(f.scanner_name != "mantis" for f in dedup_inputs[0])
    assert len(correlate_inputs) == 1
    assert all(f.scanner_name != "mantis" for f in correlate_inputs[0])
    assert len(adjust_conf_inputs) == 1
    assert all(f.scanner_name != "mantis" for f in adjust_conf_inputs[0])

    # Section 44: ScannerRun audit output
    runner = (
        await db_session.execute(
            select(ScannerRun).where(
                ScannerRun.scan_id == scan.id,
                ScannerRun.scanner_name == "mantis-advisory-review",
            )
        )
    ).scalar_one()
    meta = json.loads(runner.raw_output)
    assert meta["corroboration_enabled"] is True
    assert meta["promotions_count"] == 1


async def test_orchestrator_mantis_corroboration_negative_flag_disabled(
    db_session: AsyncSession,
    tmp_path: Path,
) -> None:
    """Section 61: When corroboration flag is disabled, HIGH 0.55 remains REVIEW."""
    proj_dir = tmp_path / "neg_flag_project"
    proj_dir.mkdir()
    (proj_dir / "app").mkdir()
    (proj_dir / "app" / "views.py").write_text("def render_user(req):\n    return req.name\n")

    project = Project(name="Neg Flag Project")
    db_session.add(project)
    await db_session.flush()

    scan = Scan(project_id=project.id, source_path=str(proj_dir))
    db_session.add(scan)
    await db_session.commit()

    semgrep_output = json.dumps({
        "results": [
            {
                "check_id": "rules.views.xss",
                "path": "app/views.py",
                "start": {"line": 100, "col": 5},
                "end": {"line": 100, "col": 20},
                "extra": {
                    "message": "Reflected XSS in view",
                    "severity": "ERROR",
                    "metadata": {"cwe": ["CWE-79"]},
                },
            }
        ]
    })
    mantis_raw = [
        {
            "id": "mantis-xss-100",
            "title": "Reflected XSS",
            "description": "XSS",
            "severity": "HIGH",
            "confidence": 0.55,
            "cwe": "CWE-79",
            "file_path": "app/views.py",
            "line_start": 103,
            "line_end": 103,
            "mantis_status": "VALID",
        }
    ]
    mock_mantis_res = MantisExecutionResult(
        capability=AgentCapability.REVIEW,
        summary="ok",
        analysis="ok",
        raw_findings=mantis_raw,
        normalized_findings=MantisAdapter().ingest_findings(mantis_raw),
        metadata={"mantis_revision": "d13c93fb8e9779801711daea0d65fffa133c3b2d"},
        duration_seconds=1.0,
    )

    # mantis_gate_corroboration_enabled is False
    settings = Settings(
        mantis_enabled=True,
        mantis_pipeline_enabled=True,
        mantis_gate_corroboration_enabled=False,
       mantis_execution_mode="read_only",
       mantis_root=tmp_path,
        allowed_workspace_root=tmp_path,
       mantis_revision="d13c93fb8e9779801711daea0d65fffa133c3b2d",
        mantis_base_url="https://api.openai.com/v1",
        mantis_api_key="test-key",
    )

    async def mock_run_command(argv, cwd=None, config=None):
        tool = argv[0]
        if "--version" in argv:
            return RunResult(return_code=0, stdout="1.0.0", stderr="")
        if tool == "semgrep":
            return RunResult(return_code=0, stdout=semgrep_output, stderr="")
        return RunResult(return_code=0, stdout="{}", stderr="")

    with (
        patch("app.services.orchestrator.get_settings", return_value=settings),
        patch("app.services.mantis_advisory.get_settings", return_value=settings),
        patch("app.scanners.base.run_command", side_effect=mock_run_command),
        patch("app.scanners.semgrep.run_command", side_effect=mock_run_command),
        patch("app.scanners.pip_audit.run_command", side_effect=mock_run_command),
        patch("app.scanners.trivy.run_command", side_effect=mock_run_command),
        patch.object(MantisSafeRuntime, "check_availability", return_value=(True, "available")),
        patch.object(MantisSafeRuntime, "analyze", new_callable=AsyncMock, return_value=mock_mantis_res),
    ):
        await run_scan(scan.id, db_session)

    await db_session.refresh(scan)
    assert scan.status == ScanStatus.COMPLETED
    assert scan.risk_gate == RiskGate.REVIEW


async def test_orchestrator_mantis_corroboration_policy_fail_open(
    db_session: AsyncSession,
    tmp_path: Path,
) -> None:
    """Section 7: Defensive fail-open when apply_mantis_corroboration raises an exception.

    Semgrep HIGH 0.55 and Mantis matching explicit VALID are present, pipeline and
    corroboration are enabled, but apply_mantis_corroboration raises RuntimeError.
    The orchestrator must catch the error, complete the scan with deterministic REVIEW,
    and persist Semgrep and Mantis findings with SINGLE_SOURCE.
    """
    proj_dir = tmp_path / "corrob_policy_fail_open_project"
    proj_dir.mkdir()
    (proj_dir / "app").mkdir()
    (proj_dir / "app" / "views.py").write_text("def render_user(req):\n    return req.name\n")

    project = Project(name="Policy Fail Open Project")
    db_session.add(project)
    await db_session.flush()

    scan = Scan(project_id=project.id, source_path=str(proj_dir))
    db_session.add(scan)
    await db_session.commit()

    semgrep_output = json.dumps(
        {
            "results": [
                {
                    "check_id": "rules.views.xss",
                    "path": "app/views.py",
                    "start": {"line": 100, "col": 5},
                    "end": {"line": 100, "col": 20},
                    "extra": {
                        "message": "Reflected XSS in view",
                        "severity": "ERROR",
                        "metadata": {"cwe": ["CWE-79"]},
                    },
                }
            ]
        }
    )

    mantis_raw = [
        {
            "id": "mantis-xss-100",
            "title": "Reflected XSS in render_user",
            "description": "User input is directly rendered",
            "severity": "HIGH",
            "confidence": 0.55,
            "cwe": "CWE-79",
            "file_path": "app/views.py",
            "line_start": 103,
            "line_end": 103,
            "mantis_status": "VALID",
            "mantis_status_explicit": True,
        }
    ]

    adapter = MantisAdapter()
    norm_mantis = adapter.ingest_findings(mantis_raw)

    mock_mantis_res = MantisExecutionResult(
        capability=AgentCapability.REVIEW,
        summary="Found valid XSS matching view",
        analysis="Detailed XSS analysis",
        raw_findings=mantis_raw,
        normalized_findings=norm_mantis,
        metadata={"mantis_revision": "d13c93fb8e9779801711daea0d65fffa133c3b2d"},
        duration_seconds=1.2,
    )

    settings = Settings(
        mantis_enabled=True,
        mantis_pipeline_enabled=True,
        mantis_gate_corroboration_enabled=True,
        mantis_execution_mode="read_only",
        mantis_root=tmp_path,
        allowed_workspace_root=tmp_path,
        mantis_revision="d13c93fb8e9779801711daea0d65fffa133c3b2d",
        mantis_base_url="https://api.openai.com/v1",
        mantis_api_key="test-key",
    )

    async def mock_run_command(argv, cwd=None, config=None):
        tool = argv[0]
        if "--version" in argv:
            return RunResult(return_code=0, stdout="1.0.0", stderr="")
        if tool == "semgrep":
            return RunResult(return_code=0, stdout=semgrep_output, stderr="")
        if tool in ("pip-audit", "trivy", "npm"):
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
        patch.object(MantisSafeRuntime, "analyze", new_callable=AsyncMock, return_value=mock_mantis_res),
        patch(
            "app.services.orchestrator.apply_mantis_corroboration",
            side_effect=RuntimeError("synthetic policy failure"),
        ),
    ):
        await run_scan(scan.id, db_session)

    await db_session.refresh(scan)
    assert scan.status == ScanStatus.COMPLETED
    assert scan.risk_gate == RiskGate.REVIEW

    findings = (
        await db_session.execute(select(Finding).where(Finding.scan_id == scan.id))
    ).scalars().all()
    semgrep_f = next(f for f in findings if f.scanner_name == "semgrep")
    mantis_f = next(f for f in findings if f.scanner_name == "mantis")

    # Deterministic Semgrep persisted normally as SINGLE_SOURCE
    assert semgrep_f.evidence_level == EvidenceLevel.SINGLE_SOURCE
    assert semgrep_f.severity == Severity.HIGH
    assert semgrep_f.confidence >= 0.50
    assert semgrep_f.risk_gate_eligible is True
    assert semgrep_f.advisory is False

    # Mantis remains SINGLE_SOURCE advisory
    assert mantis_f.evidence_level == EvidenceLevel.SINGLE_SOURCE
    assert mantis_f.risk_gate_eligible is False
    assert mantis_f.advisory is True
    assert mantis_f.correlation_group_id is None

    findings = (
        await db_session.execute(select(Finding).where(Finding.scan_id == scan.id))
    ).scalars().all()
    semgrep_f = next(f for f in findings if f.scanner_name == "semgrep")
    assert semgrep_f.evidence_level == EvidenceLevel.SINGLE_SOURCE


async def test_orchestrator_mantis_corroboration_apply_failure_fail_open(
    db_session: AsyncSession,
    tmp_path: Path,
) -> None:
    """Defensive fail-open when exception occurs inside apply_mantis_corroboration APPLY phase.

    Evaluation succeeds, but an exception is raised after entering the APPLY phase.
    apply_mantis_corroboration rolls back in-memory mutations.
    Orchestrator catches the error, completes scan with deterministic REVIEW,
    and persists Semgrep and Mantis findings as SINGLE_SOURCE (zero partial promotion).
    """
    proj_dir = tmp_path / "corrob_apply_fail_open_project"
    proj_dir.mkdir()
    (proj_dir / "app").mkdir()
    (proj_dir / "app" / "views.py").write_text("def render_user(req):\n    return req.name\n")

    project = Project(name="Apply Fail Open Project")
    db_session.add(project)
    await db_session.flush()

    scan = Scan(project_id=project.id, source_path=str(proj_dir))
    db_session.add(scan)
    await db_session.commit()

    semgrep_output = json.dumps(
        {
            "results": [
                {
                    "check_id": "rules.views.xss",
                    "path": "app/views.py",
                    "start": {"line": 100, "col": 5},
                    "end": {"line": 100, "col": 20},
                    "extra": {
                        "message": "Reflected XSS in view",
                        "severity": "ERROR",
                        "metadata": {"cwe": ["CWE-79"]},
                    },
                }
            ]
        }
    )

    mantis_raw = [
        {
            "id": "mantis-xss-100",
            "title": "Reflected XSS in render_user",
            "description": "User input directly rendered",
            "severity": "HIGH",
            "confidence": 0.55,
            "cwe": "CWE-79",
            "file_path": "app/views.py",
            "line_start": 103,
            "line_end": 103,
            "mantis_status": "VALID",
            "mantis_status_explicit": True,
        }
    ]

    adapter = MantisAdapter()
    norm_mantis = adapter.ingest_findings(mantis_raw)

    mock_mantis_res = MantisExecutionResult(
        capability=AgentCapability.REVIEW,
        summary="Found valid XSS matching view",
        analysis="Detailed XSS analysis",
        raw_findings=mantis_raw,
        normalized_findings=norm_mantis,
        metadata={"mantis_revision": "d13c93fb8e9779801711daea0d65fffa133c3b2d"},
        duration_seconds=1.2,
    )

    settings = Settings(
        mantis_enabled=True,
        mantis_pipeline_enabled=True,
        mantis_gate_corroboration_enabled=True,
        mantis_execution_mode="read_only",
        mantis_root=tmp_path,
        allowed_workspace_root=tmp_path,
        mantis_revision="d13c93fb8e9779801711daea0d65fffa133c3b2d",
        mantis_base_url="https://api.openai.com/v1",
        mantis_api_key="test-key",
    )

    async def mock_run_command(argv, cwd=None, config=None):
        tool = argv[0]
        if "--version" in argv:
            return RunResult(return_code=0, stdout="1.0.0", stderr="")
        if tool == "semgrep":
            return RunResult(return_code=0, stdout=semgrep_output, stderr="")
        if tool in ("pip-audit", "trivy", "npm"):
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
        patch.object(MantisSafeRuntime, "analyze", new_callable=AsyncMock, return_value=mock_mantis_res),
        patch(
            "app.services.agentic_corroboration._attach_corroboration_evidence",
            side_effect=RuntimeError("synthetic apply failure"),
        ),
    ):
        await run_scan(scan.id, db_session)

    await db_session.refresh(scan)
    assert scan.status == ScanStatus.COMPLETED
    assert scan.risk_gate == RiskGate.REVIEW

    findings = (
        await db_session.execute(select(Finding).where(Finding.scan_id == scan.id))
    ).scalars().all()
    semgrep_f = next(f for f in findings if f.scanner_name == "semgrep")
    mantis_f = next(f for f in findings if f.scanner_name == "mantis")

    # Deterministic Semgrep persisted normally as SINGLE_SOURCE
    assert semgrep_f.evidence_level == EvidenceLevel.SINGLE_SOURCE
    assert semgrep_f.severity == Severity.HIGH
    assert semgrep_f.confidence >= 0.50
    assert semgrep_f.risk_gate_eligible is True
    assert semgrep_f.advisory is False

    # Mantis remains SINGLE_SOURCE advisory
    assert mantis_f.evidence_level == EvidenceLevel.SINGLE_SOURCE
    assert mantis_f.risk_gate_eligible is False
    assert mantis_f.advisory is True
    assert mantis_f.correlation_group_id is None

    # No Mantis corroboration evidence persisted for Semgrep finding
    evidences = (
        await db_session.execute(
            select(FindingEvidence).where(FindingEvidence.finding_id == semgrep_f.id)
        )
    ).scalars().all()
    assert not any(e.scanner_name == "mantis" for e in evidences)

    # Correlation group remains SINGLE_SOURCE
    cg = (
        await db_session.execute(
            select(CorrelationGroup).where(CorrelationGroup.scan_id == scan.id)
        )
    ).scalar_one()
    assert cg.evidence_level == EvidenceLevel.SINGLE_SOURCE


async def test_orchestrator_mantis_corroboration_negative_pipeline_disabled(
    db_session: AsyncSession,
    tmp_path: Path,
) -> None:
    """Section 29: mantis_pipeline_enabled=False prevents Mantis execution and promotion."""
    proj_dir = tmp_path / "neg_pipe_project"
    proj_dir.mkdir()
    (proj_dir / "main.py").write_text("x = 1")

    project = Project(name="Neg Pipe Project")
    db_session.add(project)
    await db_session.flush()

    scan = Scan(project_id=project.id, source_path=str(proj_dir))
    db_session.add(scan)
    await db_session.commit()

    semgrep_output = json.dumps({
        "results": [
            {
                "check_id": "rules.views.xss",
                "path": "main.py",
                "start": {"line": 1, "col": 1},
                "end": {"line": 1, "col": 5},
                "extra": {
                    "message": "msg",
                    "severity": "ERROR",
                    "metadata": {"cwe": ["CWE-79"]},
                },
            }
        ]
    })

    # mantis_pipeline_enabled is False, gate_corroboration is True
    settings = Settings(
        mantis_enabled=True,
       mantis_pipeline_enabled=False,
       mantis_gate_corroboration_enabled=True,
       mantis_execution_mode="read_only",
        allowed_workspace_root=tmp_path,
   )

    async def mock_run_command(argv, cwd=None, config=None):
        if "--version" in argv:
            return RunResult(return_code=0, stdout="1.0.0", stderr="")
        if argv[0] == "semgrep":
            return RunResult(return_code=0, stdout=semgrep_output, stderr="")
        return RunResult(return_code=0, stdout="{}", stderr="")

    with (
        patch("app.services.orchestrator.get_settings", return_value=settings),
        patch("app.services.mantis_advisory.get_settings", return_value=settings),
        patch("app.scanners.base.run_command", side_effect=mock_run_command),
        patch("app.scanners.semgrep.run_command", side_effect=mock_run_command),
        patch("app.scanners.pip_audit.run_command", side_effect=mock_run_command),
        patch("app.scanners.trivy.run_command", side_effect=mock_run_command),
    ):
        await run_scan(scan.id, db_session)

    await db_session.refresh(scan)
    assert scan.status == ScanStatus.COMPLETED
    assert scan.risk_gate == RiskGate.REVIEW


async def test_orchestrator_mantis_only_pass(
    db_session: AsyncSession,
    tmp_path: Path,
) -> None:
    """Section 41 & 62: Zero deterministic findings + Mantis CRITICAL explicit VALID -> PASS."""
    proj_dir = tmp_path / "mantis_only_project"
    proj_dir.mkdir()
    (proj_dir / "main.py").write_text("x = 1")

    project = Project(name="Mantis Only Project")
    db_session.add(project)
    await db_session.flush()

    scan = Scan(project_id=project.id, source_path=str(proj_dir))
    db_session.add(scan)
    await db_session.commit()

    # Zero deterministic findings
    async def mock_run_command(argv, cwd=None, config=None):
        if "--version" in argv:
            return RunResult(return_code=0, stdout="1.0.0", stderr="")
        return RunResult(return_code=0, stdout="{}", stderr="")

    mantis_raw = [
        {
            "id": "mantis-crit-1",
            "title": "Critical RCE via LLM reasoning",
            "description": "Agentic finding alone",
            "severity": "CRITICAL",
            "confidence": 0.60,
            "mantis_status": "VALID",
        }
    ]
    mock_mantis_res = MantisExecutionResult(
        capability=AgentCapability.REVIEW,
        summary="Critical issue",
        analysis="Analysis",
        raw_findings=mantis_raw,
        normalized_findings=MantisAdapter().ingest_findings(mantis_raw),
        metadata={"mantis_revision": "d13c93fb8e9779801711daea0d65fffa133c3b2d"},
        duration_seconds=1.0,
    )

    settings = Settings(
        mantis_enabled=True,
        mantis_pipeline_enabled=True,
        mantis_gate_corroboration_enabled=True,
       mantis_execution_mode="read_only",
       mantis_root=tmp_path,
        allowed_workspace_root=tmp_path,
       mantis_revision="d13c93fb8e9779801711daea0d65fffa133c3b2d",
        mantis_base_url="https://api.openai.com/v1",
        mantis_api_key="test-key",
    )

    with (
        patch("app.services.orchestrator.get_settings", return_value=settings),
        patch("app.services.mantis_advisory.get_settings", return_value=settings),
        patch("app.scanners.base.run_command", side_effect=mock_run_command),
        patch("app.scanners.semgrep.run_command", side_effect=mock_run_command),
        patch("app.scanners.pip_audit.run_command", side_effect=mock_run_command),
        patch("app.scanners.trivy.run_command", side_effect=mock_run_command),
        patch.object(MantisSafeRuntime, "check_availability", return_value=(True, "available")),
        patch.object(MantisSafeRuntime, "analyze", new_callable=AsyncMock, return_value=mock_mantis_res),
    ):
        await run_scan(scan.id, db_session)

    await db_session.refresh(scan)
    assert scan.status == ScanStatus.COMPLETED
    assert scan.risk_gate == RiskGate.PASS


async def test_orchestrator_human_override_prevents_promotion(
    db_session: AsyncSession,
    tmp_path: Path,
) -> None:
    """Section 63: Deterministic finding with human disposition is never promoted by Mantis."""
    proj_dir = tmp_path / "disposition_project"
    proj_dir.mkdir()
    (proj_dir / "app.py").write_text("print('test')")

    project = Project(name="Disposition Project")
    db_session.add(project)
    await db_session.flush()

    scan = Scan(project_id=project.id, source_path=str(proj_dir))
    db_session.add(scan)
    await db_session.commit()

    semgrep_output = json.dumps({
        "results": [
            {
                "check_id": "rules.test.vuln",
                "path": "app.py",
                "start": {"line": 10, "col": 1},
                "end": {"line": 10, "col": 10},
                "extra": {
                    "message": "Vuln",
                    "severity": "ERROR",
                    "metadata": {"cwe": ["CWE-79"]},
                },
            }
        ]
    })

    # Create an active human disposition ACCEPTED_RISK
    from app.scanners.base import compute_normalized_fingerprint
    norm_fp = compute_normalized_fingerprint(
        cve=None,
        cwe="CWE-79",
        file_path="app.py",
        title="rules.test.vuln",
    )
    disp = FindingDisposition(
        project_id=project.id,
        scanner_name="semgrep",
        normalized_fingerprint=norm_fp,
        status=FindingStatus.ACCEPTED_RISK,
        justification="Risk accepted by security team",
        actor="human_admin",
    )
    db_session.add(disp)
    await db_session.commit()

    mantis_raw = [
        {
            "id": "mantis-vuln-disp",
            "title": "rules.test.vuln",
            "description": "Cross site scripting",
            "severity": "HIGH",
            "confidence": 0.55,
            "cwe": "CWE-79",
            "file_path": "app.py",
            "line_start": 10,
            "line_end": 10,
            "mantis_status": "VALID",
        }
    ]
    mock_mantis_res = MantisExecutionResult(
        capability=AgentCapability.REVIEW,
        summary="ok",
        analysis="ok",
        raw_findings=mantis_raw,
        normalized_findings=MantisAdapter().ingest_findings(mantis_raw),
        metadata={"mantis_revision": "d13c93fb8e9779801711daea0d65fffa133c3b2d"},
        duration_seconds=1.0,
    )

    settings = Settings(
        mantis_enabled=True,
        mantis_pipeline_enabled=True,
        mantis_gate_corroboration_enabled=True,
       mantis_execution_mode="read_only",
       mantis_root=tmp_path,
        allowed_workspace_root=tmp_path,
       mantis_revision="d13c93fb8e9779801711daea0d65fffa133c3b2d",
        mantis_base_url="https://api.openai.com/v1",
        mantis_api_key="test-key",
    )

    async def mock_run_command(argv, cwd=None, config=None):
        if "--version" in argv:
            return RunResult(return_code=0, stdout="1.0.0", stderr="")
        if argv[0] == "semgrep":
            return RunResult(return_code=0, stdout=semgrep_output, stderr="")
        return RunResult(return_code=0, stdout="{}", stderr="")

    with (
        patch("app.services.orchestrator.get_settings", return_value=settings),
        patch("app.services.mantis_advisory.get_settings", return_value=settings),
        patch("app.scanners.base.run_command", side_effect=mock_run_command),
        patch("app.scanners.semgrep.run_command", side_effect=mock_run_command),
        patch("app.scanners.pip_audit.run_command", side_effect=mock_run_command),
        patch("app.scanners.trivy.run_command", side_effect=mock_run_command),
        patch.object(MantisSafeRuntime, "check_availability", return_value=(True, "available")),
        patch.object(MantisSafeRuntime, "analyze", new_callable=AsyncMock, return_value=mock_mantis_res),
    ):
        await run_scan(scan.id, db_session)

    await db_session.refresh(scan)
    assert scan.status == ScanStatus.COMPLETED
    assert scan.risk_gate == RiskGate.PASS  # ACCEPTED_RISK findings are non-actionable

    findings = (
        await db_session.execute(select(Finding).where(Finding.scan_id == scan.id))
    ).scalars().all()
    semgrep_f = next(f for f in findings if f.scanner_name == "semgrep")
    assert semgrep_f.status == FindingStatus.ACCEPTED_RISK
    assert semgrep_f.evidence_level == EvidenceLevel.SINGLE_SOURCE


async def test_orchestrator_mantis_repro_status_never_runtime_validated(
    db_session: AsyncSession,
    tmp_path: Path,
) -> None:
    """Section 23 & 64: Mantis claim of 'reproduced'/'verified' NEVER creates RUNTIME_VALIDATED."""
    proj_dir = tmp_path / "repro_project"
    proj_dir.mkdir()
    (proj_dir / "vuln.py").write_text("x = 1")

    project = Project(name="Repro Project")
    db_session.add(project)
    await db_session.flush()

    scan = Scan(project_id=project.id, source_path=str(proj_dir))
    db_session.add(scan)
    await db_session.commit()

    semgrep_output = json.dumps({
        "results": [
            {
                "check_id": "rules.test.rce",
                "path": "vuln.py",
                "start": {"line": 20, "col": 1},
                "end": {"line": 20, "col": 10},
                "extra": {
                    "message": "Command Injection",
                    "severity": "ERROR",
                    "metadata": {"cwe": ["CWE-78"]},
                },
            }
        ]
    })

    mantis_raw = [
        {
            "id": "mantis-rce-repro",
            "title": "Command Injection in vuln.py",
            "description": "Verified command injection",
            "severity": "HIGH",
            "confidence": 0.60,
            "cwe": "CWE-78",
            "file_path": "vuln.py",
            "line_start": 20,
            "line_end": 20,
            "mantis_status": "VALID",
            "repro_status": "reproduced",
            "verified": True,
            "exploited": True,
        }
    ]
    mock_mantis_res = MantisExecutionResult(
        capability=AgentCapability.REVIEW,
        summary="ok",
        analysis="ok",
        raw_findings=mantis_raw,
        normalized_findings=MantisAdapter().ingest_findings(mantis_raw),
        metadata={"mantis_revision": "d13c93fb8e9779801711daea0d65fffa133c3b2d"},
        duration_seconds=1.0,
    )

    settings = Settings(
        mantis_enabled=True,
        mantis_pipeline_enabled=True,
        mantis_gate_corroboration_enabled=True,
       mantis_execution_mode="read_only",
       mantis_root=tmp_path,
        allowed_workspace_root=tmp_path,
       mantis_revision="d13c93fb8e9779801711daea0d65fffa133c3b2d",
        mantis_base_url="https://api.openai.com/v1",
        mantis_api_key="test-key",
    )

    async def mock_run_command(argv, cwd=None, config=None):
        if "--version" in argv:
            return RunResult(return_code=0, stdout="1.0.0", stderr="")
        if argv[0] == "semgrep":
            return RunResult(return_code=0, stdout=semgrep_output, stderr="")
        return RunResult(return_code=0, stdout="{}", stderr="")

    with (
        patch("app.services.orchestrator.get_settings", return_value=settings),
        patch("app.services.mantis_advisory.get_settings", return_value=settings),
        patch("app.scanners.base.run_command", side_effect=mock_run_command),
        patch("app.scanners.semgrep.run_command", side_effect=mock_run_command),
        patch("app.scanners.pip_audit.run_command", side_effect=mock_run_command),
        patch("app.scanners.trivy.run_command", side_effect=mock_run_command),
        patch.object(MantisSafeRuntime, "check_availability", return_value=(True, "available")),
        patch.object(MantisSafeRuntime, "analyze", new_callable=AsyncMock, return_value=mock_mantis_res),
    ):
        await run_scan(scan.id, db_session)

    findings = (
        await db_session.execute(select(Finding).where(Finding.scan_id == scan.id))
    ).scalars().all()
    semgrep_f = next(f for f in findings if f.scanner_name == "semgrep")
    assert semgrep_f.evidence_level == EvidenceLevel.CORROBORATED_STATIC
    assert semgrep_f.evidence_level != EvidenceLevel.RUNTIME_VALIDATED


async def test_orchestrator_mantis_corroboration_fail_open(
    db_session: AsyncSession,
    tmp_path: Path,
) -> None:
    """Section 27: Provider/runtime failure during Mantis stage does not break main scan."""
    proj_dir = tmp_path / "fail_open_project"
    proj_dir.mkdir()
    (proj_dir / "main.py").write_text("x = 1")

    project = Project(name="Fail Open Project")
    db_session.add(project)
    await db_session.flush()

    scan = Scan(project_id=project.id, source_path=str(proj_dir))
    db_session.add(scan)
    await db_session.commit()

    semgrep_output = json.dumps({
        "results": [
            {
                "check_id": "rules.test.xss",
                "path": "main.py",
                "start": {"line": 1, "col": 1},
                "end": {"line": 1, "col": 5},
                "extra": {
                    "message": "xss",
                    "severity": "ERROR",
                    "metadata": {"cwe": ["CWE-79"]},
                },
            }
        ]
    })

    settings = Settings(
        mantis_enabled=True,
        mantis_pipeline_enabled=True,
        mantis_gate_corroboration_enabled=True,
       mantis_execution_mode="read_only",
       mantis_root=tmp_path,
        allowed_workspace_root=tmp_path,
       mantis_revision="d13c93fb8e9779801711daea0d65fffa133c3b2d",
        mantis_base_url="https://api.openai.com/v1",
        mantis_api_key="test-key",
    )

    async def mock_run_command(argv, cwd=None, config=None):
        if "--version" in argv:
            return RunResult(return_code=0, stdout="1.0.0", stderr="")
        if argv[0] == "semgrep":
            return RunResult(return_code=0, stdout=semgrep_output, stderr="")
        return RunResult(return_code=0, stdout="{}", stderr="")

    with (
        patch("app.services.orchestrator.get_settings", return_value=settings),
        patch("app.services.mantis_advisory.get_settings", return_value=settings),
        patch("app.scanners.base.run_command", side_effect=mock_run_command),
        patch("app.scanners.semgrep.run_command", side_effect=mock_run_command),
        patch("app.scanners.pip_audit.run_command", side_effect=mock_run_command),
        patch("app.scanners.trivy.run_command", side_effect=mock_run_command),
        patch.object(MantisSafeRuntime, "check_availability", return_value=(True, "available")),
        patch.object(MantisSafeRuntime, "analyze", new_callable=AsyncMock, side_effect=RuntimeError("500 Internal Server Error")),
    ):
        await run_scan(scan.id, db_session)

    await db_session.refresh(scan)
    assert scan.status == ScanStatus.COMPLETED
    assert scan.risk_gate == RiskGate.REVIEW  # Semgrep alone is HIGH 0.50 -> REVIEW
