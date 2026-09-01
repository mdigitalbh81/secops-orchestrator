"""Tests for scan orchestrator service."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.enums import RiskGate, ScannerRunStatus, ScanStatus
from app.models.finding import Finding, FindingEvidence
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
        await db_session.execute(
            select(ScannerRun).where(ScannerRun.scan_id == scan.id)
        )
    ).scalars().all()
    statuses = {r.scanner_name: r.status for r in runs}
    assert statuses["semgrep"] == ScannerRunStatus.COMPLETED
    assert statuses["npm-audit"] == ScannerRunStatus.COMPLETED
    assert statuses["pip-audit"] == ScannerRunStatus.NOT_APPLICABLE
    assert statuses["trivy"] == ScannerRunStatus.COMPLETED

    findings = (
        await db_session.execute(
            select(Finding).where(Finding.scan_id == scan.id)
        )
    ).scalars().all()
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
        await db_session.execute(
            select(ScannerRun).where(ScannerRun.scan_id == scan.id)
        )
    ).scalars().all()
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
        await db_session.execute(
            select(ScannerRun).where(ScannerRun.scan_id == scan.id)
        )
    ).scalars().all()
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
        await db_session.execute(
            select(ScannerRun).where(ScannerRun.scan_id == scan.id)
        )
    ).scalars().all()
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
        await db_session.execute(
            select(ScannerRun).where(ScannerRun.scan_id == scan.id)
        )
    ).scalars().all()
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
        await db_session.execute(
            select(ScannerRun).where(ScannerRun.scan_id == scan.id)
        )
    ).scalars().all()
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
    evidences = (
        await db_session.execute(select(FindingEvidence))
    ).scalars().all()
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

    sensitive_stdout = json.dumps({
        "vulnerabilities": {
            "bad-pkg": {
                "name": "bad-pkg",
                "severity": "high",
                "title": "Leaked AWS: AKIAIOSFODNN7EXAMPLE and api_key='sk_live_1234567890abcdef\'",
                "via": [{"cve": "CVE-2023-9999", "title": "secret leak"}]
            }
        }
    })

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
        await db_session.execute(
            select(ScannerRun).where(ScannerRun.scan_id == scan.id)
        )
    ).scalars().all()
    npm_run = next(r for r in runs if r.scanner_name == "npm-audit")
    raw = json.loads(npm_run.raw_output)
    subtarget = raw["subtargets"][0]

    assert subtarget["status"] == "COMPLETED"
    assert "[REDACTED_SECRET]" in subtarget["stdout"]
    assert "AKIAIOSFODNN7EXAMPLE" not in subtarget["stdout"]
    assert "[REDACTED_SECRET]" in subtarget["stderr"]
    assert "AKIAIOSFODNN7EXAMPLE" not in subtarget["stderr"]
