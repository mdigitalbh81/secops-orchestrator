from unittest.mock import patch

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.enums import RiskGate, ScannerRunStatus, ScanStatus, Severity
from app.models.finding import Finding
from app.models.project import Project
from app.models.scan import Scan
from app.models.scanner_run import ScannerRun


async def test_health_endpoint(client: AsyncClient):
    response = await client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


async def test_create_project(client: AsyncClient):
    payload = {
        "name": "Acme API",
        "repository_url": "https://github.com/acme/api",
        "description": "Core payment service",
    }
    response = await client.post("/api/projects", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert data["name"] == "Acme API"
    assert data["id"] is not None
    assert data["repository_url"] == "https://github.com/acme/api"


async def test_create_scan(client: AsyncClient, tmp_path):
    # Create project first
    proj_res = await client.post("/api/projects", json={"name": "Scan Test"})
    assert proj_res.status_code == 201
    project_id = proj_res.json()["id"]

    with patch("app.api.routes.enqueue_scan") as mock_enqueue:
        mock_enqueue.return_value = True
        scan_res = await client.post(
            "/api/scans",
            json={"project_id": project_id, "source_path": str(tmp_path)},
        )
        assert scan_res.status_code == 202
        data = scan_res.json()
        assert data["project_id"] == project_id
        assert data["status"] == "PENDING"
        assert data["id"] is not None


async def test_create_scan_nonexistent_project(client: AsyncClient, tmp_path):
    response = await client.post(
        "/api/scans",
        json={"project_id": "non-existent-uuid", "source_path": str(tmp_path)},
    )
    assert response.status_code == 404


async def test_get_scan_endpoints(client: AsyncClient, tmp_path):
    proj_res = await client.post("/api/projects", json={"name": "Query Test"})
    project_id = proj_res.json()["id"]

    with patch("app.api.routes.enqueue_scan"):
        scan_res = await client.post(
            "/api/scans",
            json={"project_id": project_id, "source_path": str(tmp_path)},
        )
        scan_id = scan_res.json()["id"]

    # GET /api/scans/{scan_id}
    res = await client.get(f"/api/scans/{scan_id}")
    assert res.status_code == 200
    assert res.json()["id"] == scan_id

    # GET non-existent scan -> 404
    res_404 = await client.get("/api/scans/00000000-0000-0000-0000-000000000000")
    assert res_404.status_code == 404

    # GET non-existent scan summary -> 404
    res_summary_404 = await client.get("/api/scans/00000000-0000-0000-0000-000000000000/summary")
    assert res_summary_404.status_code == 404

    # GET /api/scans/{scan_id}/scanner-runs
    res_runs = await client.get(f"/api/scans/{scan_id}/scanner-runs")
    assert res_runs.status_code == 200
    assert isinstance(res_runs.json(), list)

    # GET /api/scans/{scan_id}/findings
    res_findings = await client.get(f"/api/scans/{scan_id}/findings")
    assert res_findings.status_code == 200
    assert isinstance(res_findings.json(), list)

    # GET /api/scans/{scan_id}/summary
    res_summary = await client.get(f"/api/scans/{scan_id}/summary")
    assert res_summary.status_code == 200
    summary = res_summary.json()
    assert summary["scan_id"] == scan_id
    assert "totals" in summary
    assert "scanner_runs" in summary


async def test_summary_with_all_severities(client: AsyncClient, db_session: AsyncSession, tmp_path):
    project = Project(name="Summary Detailed Test")
    db_session.add(project)
    await db_session.flush()

    scan = Scan(
        project_id=project.id,
        source_path=str(tmp_path),
        status=ScanStatus.COMPLETED,
        risk_gate=RiskGate.BLOCKED,
    )
    db_session.add(scan)
    await db_session.flush()

    # Add scanner runs
    r1 = ScannerRun(
        scan_id=scan.id,
        scanner_name="semgrep",
        status=ScannerRunStatus.COMPLETED,
    )
    r2 = ScannerRun(
        scan_id=scan.id,
        scanner_name="pip-audit",
        status=ScannerRunStatus.FAILED,
    )
    db_session.add_all([r1, r2])

    # Add findings of each severity
    severities = [
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
        Severity.INFO,
        Severity.UNKNOWN,
    ]
    for idx, sev in enumerate(severities):
        f = Finding(
            scan_id=scan.id,
            scanner_name="semgrep",
            title=f"Finding {idx}",
            severity=sev,
            confidence=0.8,
            raw_fingerprint=f"raw_{idx}",
            normalized_fingerprint=f"norm_{idx}",
        )
        db_session.add(f)

    await db_session.commit()

    res = await client.get(f"/api/scans/{scan.id}/summary")
    assert res.status_code == 200
    data = res.json()
    assert data["totals"]["critical"] == 1
    assert data["totals"]["high"] == 1
    assert data["totals"]["medium"] == 1
    assert data["totals"]["low"] == 1
    assert data["totals"]["info"] == 1
    assert data["totals"]["unknown"] == 1
    assert data["scanner_runs"]["semgrep"] == "completed"
    assert data["scanner_runs"]["pip-audit"] == "failed"


async def test_create_scan_path_traversal_rejected(client: AsyncClient) -> None:
    proj_res = await client.post("/api/projects", json={"name": "Traversal Test"})
    assert proj_res.status_code == 201
    project_id = proj_res.json()["id"]

    response = await client.post(
        "/api/scans",
        json={"project_id": project_id, "source_path": "/etc/shadow"},
    )
    assert response.status_code == 400
