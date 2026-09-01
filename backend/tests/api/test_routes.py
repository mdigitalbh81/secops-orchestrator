from __future__ import annotations

from unittest.mock import patch

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.correlation import CorrelationGroup
from app.models.enums import (
    EvidenceLevel,
    FindingStatus,
    RiskGate,
    ScannerRunStatus,
    ScanStatus,
    Severity,
)
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

    # GET /api/scans/{scan_id}/correlations
    res_corrs = await client.get(f"/api/scans/{scan_id}/correlations")
    assert res_corrs.status_code == 200
    assert isinstance(res_corrs.json(), list)

    # GET /api/scans/{scan_id}/evidence-summary
    res_evidence = await client.get(f"/api/scans/{scan_id}/evidence-summary")
    assert res_evidence.status_code == 200
    assert res_evidence.json()["scan_id"] == scan_id

    # GET /api/scans/{scan_id}/summary
    res_summary = await client.get(f"/api/scans/{scan_id}/summary")
    assert res_summary.status_code == 200
    summary = res_summary.json()
    assert summary["scan_id"] == scan_id
    assert "totals" in summary
    assert "correlated_totals" in summary
    assert "evidence_levels" in summary
    assert "scanner_runs" in summary


async def test_summary_and_correlations_detailed(
    client: AsyncClient, db_session: AsyncSession, tmp_path
):
    project = Project(name="Phase2 Route Test")
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

    # Add correlation group
    group = CorrelationGroup(
        scan_id=scan.id,
        canonical_title="SQL Injection in Repository",
        canonical_cwe="CWE-89",
        severity=Severity.HIGH,
        confidence=0.90,
        evidence_level=EvidenceLevel.CORROBORATED_STATIC,
        status=FindingStatus.OPEN,
    )
    db_session.add(group)
    await db_session.flush()

    # Add findings
    f1 = Finding(
        scan_id=scan.id,
        scanner_name="semgrep",
        title="SQL injection pattern",
        severity=Severity.HIGH,
        confidence=0.70,
        evidence_level=EvidenceLevel.CORROBORATED_STATIC,
        correlation_group_id=group.id,
        cwe="CWE-89",
        file_path="app/db.py",
        raw_fingerprint="raw_1",
        normalized_fingerprint="norm_1",
    )
    f2 = Finding(
        scan_id=scan.id,
        scanner_name="codeql",
        title="SQL query built from user-controlled sources",
        severity=Severity.HIGH,
        confidence=0.85,
        evidence_level=EvidenceLevel.CORROBORATED_STATIC,
        correlation_group_id=group.id,
        cwe="CWE-89",
        file_path="app/db.py",
        raw_fingerprint="raw_2",
        normalized_fingerprint="norm_2",
    )
    db_session.add_all([f1, f2])

    # Add scanner runs
    r1 = ScannerRun(
        scan_id=scan.id,
        scanner_name="semgrep",
        status=ScannerRunStatus.COMPLETED,
    )
    r2 = ScannerRun(
        scan_id=scan.id,
        scanner_name="codeql",
        status=ScannerRunStatus.COMPLETED,
    )
    db_session.add_all([r1, r2])
    await db_session.commit()

    # GET /api/scans/{scan.id}/correlations
    res_corr = await client.get(f"/api/scans/{scan.id}/correlations")
    assert res_corr.status_code == 200
    corr_list = res_corr.json()
    assert len(corr_list) == 1
    assert corr_list[0]["canonical_cwe"] == "CWE-89"
    assert corr_list[0]["evidence_level"] == "CORROBORATED_STATIC"

    # GET /api/scans/{scan.id}/correlations/{group.id}
    res_detail = await client.get(f"/api/scans/{scan.id}/correlations/{group.id}")
    assert res_detail.status_code == 200
    assert res_detail.json()["id"] == group.id

    # GET /api/scans/{scan.id}/evidence-summary
    res_ev = await client.get(f"/api/scans/{scan.id}/evidence-summary")
    assert res_ev.status_code == 200
    ev_data = res_ev.json()
    assert ev_data["total_findings"] == 2
    assert ev_data["total_correlations"] == 1
    assert ev_data["corroborated_static_count"] == 2

    # GET /api/scans/{scan.id}/summary
    res_summary = await client.get(f"/api/scans/{scan.id}/summary")
    assert res_summary.status_code == 200
    sum_data = res_summary.json()
    assert sum_data["totals"]["high"] == 2
    assert sum_data["correlated_totals"]["high"] == 1
    assert sum_data["evidence_levels"]["CORROBORATED_STATIC"] == 2


async def test_create_scan_path_traversal_rejected(client: AsyncClient) -> None:
    proj_res = await client.post("/api/projects", json={"name": "Traversal Test"})
    assert proj_res.status_code == 201
    project_id = proj_res.json()["id"]

    response = await client.post(
        "/api/scans",
        json={"project_id": project_id, "source_path": "/etc/shadow"},
    )
    assert response.status_code == 400


async def test_partial_scanner_run_in_summary_and_runs_api(
    client: AsyncClient,
    db_session: AsyncSession,
    tmp_path,
):
    project = Project(name="Partial Route Test")
    db_session.add(project)
    await db_session.flush()

    scan = Scan(
        project_id=project.id,
        source_path=str(tmp_path),
        status=ScanStatus.COMPLETED,
        risk_gate=RiskGate.PASS,
    )
    db_session.add(scan)
    await db_session.flush()

    r1 = ScannerRun(
        scan_id=scan.id,
        scanner_name="npm-audit",
        status=ScannerRunStatus.PARTIAL,
        error_message="1 of 2 target(s) failed",
    )
    r2 = ScannerRun(
        scan_id=scan.id,
        scanner_name="semgrep",
        status=ScannerRunStatus.COMPLETED,
    )
    db_session.add_all([r1, r2])
    await db_session.commit()

    # GET /api/scans/{scan.id}/scanner-runs
    res_runs = await client.get(f"/api/scans/{scan.id}/scanner-runs")
    assert res_runs.status_code == 200
    runs = res_runs.json()
    npm_run = next(r for r in runs if r["scanner_name"] == "npm-audit")
    assert npm_run["status"] == "PARTIAL"

    # GET /api/scans/{scan.id}/summary
    res_sum = await client.get(f"/api/scans/{scan.id}/summary")
    assert res_sum.status_code == 200
    sum_data = res_sum.json()
    assert sum_data["scanner_runs"]["npm-audit"] == "partial"
    assert sum_data["scanner_runs"]["semgrep"] == "completed"
