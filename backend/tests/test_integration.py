import os
import shutil
import subprocess
import uuid
from pathlib import Path
from unittest.mock import patch

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.enums import RiskGate, ScanStatus
from app.security.runner import RunResult
from app.services.orchestrator import run_scan

BACKEND_DIR = Path(__file__).resolve().parents[1]


async def test_full_integration_multi_stack_scan(
    client: AsyncClient,
    db_session: AsyncSession,
    tmp_path: Path,
    semgrep_json: str,
    npm_audit_json: str,
    pip_audit_json: str,
    trivy_json: str,
    codeql_sarif: str,
):
    """End-to-end integration test of a multi-language project."""
    # Create fixture repo structure
    project_dir = tmp_path / "full_app"
    project_dir.mkdir()
    (project_dir / "package.json").write_text('{"name": "test-app"}')
    (project_dir / "requirements.txt").write_text("urllib3==1.26.4\njinja2==2.11.2\n")
    (project_dir / "Dockerfile").write_text("FROM python:3.12-slim\n")
    (project_dir / "main.py").write_text("import pickle\nimport os")

    # Create project via API
    proj_res = await client.post(
        "/api/projects",
        json={
            "name": "Integration Multi-Stack App",
            "description": "Full end-to-end test",
        },
    )
    assert proj_res.status_code == 201
    project_id = proj_res.json()["id"]

    # Create scan via API
    with patch("app.api.routes.enqueue_scan"):
        scan_res = await client.post(
            "/api/scans",
            json={"project_id": project_id, "source_path": str(project_dir)},
        )
    assert scan_res.status_code == 202
    scan_id = scan_res.json()["id"]

    # Mock scanner tool executions offline
    async def mock_run_command(argv, cwd=None, config=None):
        tool = argv[0]
        if tool == "semgrep":
            if "--version" in argv:
                return RunResult(return_code=0, stdout="1.70.0", stderr="")
            return RunResult(return_code=0, stdout=semgrep_json, stderr="")
        elif tool == "codeql":
            if "version" in argv:
                return RunResult(return_code=0, stdout='{"version": "2.19.0"}', stderr="")
            if "create" in argv:
                return RunResult(return_code=0, stdout="DB created", stderr="")
            if "analyze" in argv:
                for arg in argv:
                    if arg.startswith("--output="):
                        out_path = Path(arg.split("=", 1)[1])
                        out_path.write_text(codeql_sarif, encoding="utf-8")
                return RunResult(return_code=0, stdout="Analyzed", stderr="")
            return RunResult(return_code=0, stdout=codeql_sarif, stderr="")
        elif tool == "npm":
            if "--version" in argv:
                return RunResult(return_code=0, stdout="10.0.0", stderr="")
            return RunResult(return_code=1, stdout=npm_audit_json, stderr="")
        elif tool == "pip-audit":
            if "--version" in argv:
                return RunResult(return_code=0, stdout="2.7.0", stderr="")
            return RunResult(return_code=1, stdout=pip_audit_json, stderr="")
        elif tool == "trivy":
            if "--version" in argv:
                return RunResult(return_code=0, stdout="0.50.0", stderr="")
            return RunResult(return_code=0, stdout=trivy_json, stderr="")
        return RunResult(return_code=-1, stdout="", stderr="command not found")

    with (
        patch("app.scanners.base.run_command", side_effect=mock_run_command),
        patch("app.scanners.semgrep.run_command", side_effect=mock_run_command),
        patch("app.scanners.codeql.run_command", side_effect=mock_run_command),
        patch("app.scanners.npm_audit.run_command", side_effect=mock_run_command),
        patch("app.scanners.pip_audit.run_command", side_effect=mock_run_command),
        patch("app.scanners.trivy.run_command", side_effect=mock_run_command),
    ):
        await run_scan(scan_id, db_session)

    # Query summary via API
    summary_res = await client.get(f"/api/scans/{scan_id}/summary")
    assert summary_res.status_code == 200
    summary = summary_res.json()
    assert summary["status"] == ScanStatus.COMPLETED
    assert summary["risk_gate"] == RiskGate.BLOCKED
    assert summary["totals"]["critical"] > 0
    assert summary["totals"]["high"] > 0
    assert summary["scanner_runs"]["semgrep"] == "completed"
    assert summary["scanner_runs"]["codeql"] == "completed"
    assert summary["scanner_runs"]["npm-audit"] == "completed"
    assert summary["scanner_runs"]["pip-audit"] == "completed"
    assert summary["scanner_runs"]["trivy"] == "completed"

    # Query correlations via API
    corr_res = await client.get(f"/api/scans/{scan_id}/correlations")
    assert corr_res.status_code == 200
    corrs = corr_res.json()
    assert len(corrs) > 0

    # Query evidence summary via API
    ev_res = await client.get(f"/api/scans/{scan_id}/evidence-summary")
    assert ev_res.status_code == 200
    ev_data = ev_res.json()
    assert ev_data["total_findings"] > 0
    assert ev_data["total_correlations"] > 0

    # Query findings via API
    findings_res = await client.get(f"/api/scans/{scan_id}/findings")
    assert findings_res.status_code == 200
    findings = findings_res.json()
    assert len(findings) > 0

    lodash_findings = [f for f in findings if f.get("package_name") == "lodash"]
    assert len(lodash_findings) == 2
    lodash_scanners = {f["scanner_name"] for f in lodash_findings}
    assert lodash_scanners == {"npm-audit", "trivy"}
    lodash_corrs = [
        c
        for c in corrs
        if any(f.get("package_name") == "lodash" for f in c.get("findings", []))
        or "lodash" in c.get("canonical_title", "").lower()
    ]
    assert len(lodash_corrs) == 1
    assert lodash_corrs[0]["evidence_level"] == "CORROBORATED_STATIC"
    assert lodash_corrs[0]["confidence"] >= 0.85
    assert len(lodash_corrs[0]["findings"]) == 2


BACKEND_DIR = Path(__file__).resolve().parents[1]


def _postgres_is_available() -> bool:
    try:
        res = subprocess.run(
            ["docker", "exec", "secops-postgres", "psql", "-U", "secops", "-c", "SELECT 1;"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return res.returncode == 0
    except Exception:
        return False


@pytest.mark.skipif(not _postgres_is_available(), reason="PostgreSQL container not accessible")
def test_migration_005_safe_downgrade_roundtrip() -> None:
    """Validate 004 -> 005 -> insert DAST_ONLY scan (source_path=NULL) -> downgrade 004 -> upgrade 005."""
    disposable_db = f"secops_test_disp_{uuid.uuid4().hex[:8]}"

    # 1. Create disposable database
    create_res = subprocess.run(
        ["docker", "exec", "secops-postgres", "psql", "-U", "secops", "-c", f"CREATE DATABASE {disposable_db};"],
        capture_output=True,
        text=True,
    )
    assert create_res.returncode == 0, f"Failed to create disposable db: {create_res.stderr}"

    env = os.environ.copy()
    env["SECOPS_DATABASE_URL"] = f"postgresql+asyncpg://secops:secops@localhost:5432/{disposable_db}"
    env["SECOPS_DATABASE_URL_SYNC"] = f"postgresql://secops:secops@localhost:5432/{disposable_db}"

    alembic_bin = shutil.which("alembic") or "/home/felps/projetos/secops-orchestrator/.venv/bin/alembic"

    try:
        # 2. Upgrade to 004
        res = subprocess.run(
            [alembic_bin, "upgrade", "004"],
            cwd=str(BACKEND_DIR),
            env=env,
            capture_output=True,
            text=True,
        )
        assert res.returncode == 0, f"Upgrade to 004 failed: {res.stderr}"

        # 3. Upgrade to 005
        res = subprocess.run(
            [alembic_bin, "upgrade", "005"],
            cwd=str(BACKEND_DIR),
            env=env,
            capture_output=True,
            text=True,
        )
        assert res.returncode == 0, f"Upgrade to 005 failed: {res.stderr}"

        # 4. Insert project and DAST_ONLY scan with source_path NULL
        scan_id = f"scan-dast-{uuid.uuid4().hex[:8]}"
        proj_id = f"proj-dast-{uuid.uuid4().hex[:8]}"
        insert_sql = f"""
        INSERT INTO projects (id, name, created_at, updated_at)
        VALUES ('{proj_id}', 'DAST Only Downgrade Test', NOW(), NOW());

        INSERT INTO scans (id, project_id, source_path, target_url, scan_mode, status, created_at)
        VALUES ('{scan_id}', '{proj_id}', NULL, 'https://app.example.com', 'DAST_ONLY', 'COMPLETED', NOW());
        """
        res = subprocess.run(
            ["docker", "exec", "secops-postgres", "psql", "-U", "secops", "-d", disposable_db, "-c", insert_sql],
            capture_output=True,
            text=True,
        )
        assert res.returncode == 0, f"Failed to insert test DAST scan: {res.stderr}"

        # 5. Downgrade to 004
        res = subprocess.run(
            [alembic_bin, "downgrade", "004"],
            cwd=str(BACKEND_DIR),
            env=env,
            capture_output=True,
            text=True,
        )
        assert res.returncode == 0, f"Downgrade 004 failed with DAST-only scan present: {res.stderr}"

        # 6. Confirm scan was not deleted and source_path is now non-null
        check_res = subprocess.run(
            ["docker", "exec", "secops-postgres", "psql", "-U", "secops", "-d", disposable_db, "-t", "-c",
             f"SELECT id, source_path FROM scans WHERE id = '{scan_id}';"],
            capture_output=True,
            text=True,
        )
        row = check_res.stdout.strip()
        assert row, "Scan was deleted during downgrade!"
        parts = [p.strip() for p in row.split("|")]
        retrieved_id, retrieved_path = parts[0], parts[1]
        assert retrieved_id == scan_id
        expected_path = f"/tmp/secops-workspaces/dast-only-downgraded/{scan_id}"
        assert retrieved_path == expected_path, f"Expected {expected_path}, got {retrieved_path}"

        # 7. Upgrade back to 005
        res = subprocess.run(
            [alembic_bin, "upgrade", "005"],
            cwd=str(BACKEND_DIR),
            env=env,
            capture_output=True,
            text=True,
        )
        assert res.returncode == 0, f"Upgrade back to 005 failed: {res.stderr}"

    finally:
        # Drop disposable database
        subprocess.run(
            ["docker", "exec", "secops-postgres", "psql", "-U", "secops", "-c", f"DROP DATABASE IF EXISTS {disposable_db};"],
            capture_output=True,
            text=True,
        )
