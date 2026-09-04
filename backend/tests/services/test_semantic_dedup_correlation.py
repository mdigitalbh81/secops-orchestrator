from __future__ import annotations

from unittest.mock import patch

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.correlation import CorrelationGroup
from app.models.enums import EvidenceLevel, FindingStatus, RiskGate, ScanStatus, Severity
from app.models.finding import Finding, FindingEvidence
from app.models.project import Project
from app.models.scan import Scan
from app.scanners.base import (
    NormalizedFinding,
    compute_normalized_fingerprint,
)
from app.security.runner import RunResult
from app.services.correlation import are_findings_correlated, correlate_findings
from app.services.dedup import deduplicate_findings
from app.services.orchestrator import run_scan


def test_1_same_scanner_same_fingerprint():
    fp = compute_normalized_fingerprint(cwe="CWE-89", file_path="app/db.py", title="sql-inject")
    f1 = NormalizedFinding(
        title="sql-inject",
        description="Semgrep detection 1",
        severity=Severity.HIGH,
        confidence=0.50,
        scanner_name="semgrep",
        cwe="CWE-89",
        file_path="app/db.py",
        normalized_fingerprint=fp,
    )
    f2 = NormalizedFinding(
        title="sql-inject",
        description="Semgrep detection 2",
        severity=Severity.HIGH,
        confidence=0.50,
        scanner_name="semgrep",
        cwe="CWE-89",
        file_path="app/db.py",
        normalized_fingerprint=fp,
    )
    deduped = deduplicate_findings([f1, f2])
    assert len(deduped) == 1
    assert deduped[0].evidence_level == EvidenceLevel.SINGLE_SOURCE
    assert deduped[0].confidence == 0.50

    groups = correlate_findings(deduped, scan_id="scan-1")
    assert len(groups) == 1
    assert groups[0].evidence_level == EvidenceLevel.SINGLE_SOURCE
    assert groups[0].confidence == 0.50
    assert len(groups[0].findings) == 1


def test_2_different_scanners_same_fingerprint():
    fp = compute_normalized_fingerprint(cwe="CWE-89", file_path="app/db.py", title="sql-vuln")
    f1 = NormalizedFinding(
        title="sql-vuln",
        description="Semgrep detection",
        severity=Severity.HIGH,
        confidence=0.50,
        scanner_name="semgrep",
        cwe="CWE-89",
        file_path="app/db.py",
        normalized_fingerprint=fp,
    )
    f2 = NormalizedFinding(
        title="sql-vuln",
        description="CodeQL detection",
        severity=Severity.HIGH,
        confidence=0.70,
        scanner_name="codeql",
        cwe="CWE-89",
        file_path="app/db.py",
        normalized_fingerprint=fp,
    )
    deduped = deduplicate_findings([f1, f2])
    assert len(deduped) == 2

    groups = correlate_findings(deduped, scan_id="scan-2")
    assert len(groups) == 1
    assert groups[0].evidence_level == EvidenceLevel.CORROBORATED_STATIC
    assert len(groups[0].findings) == 2
    scanners = {f.scanner_name for f in groups[0].findings}
    assert scanners == {"semgrep", "codeql"}
    assert all(f.evidence_level == EvidenceLevel.CORROBORATED_STATIC for f in groups[0].findings)


def test_3_different_scanners_same_cve_package():
    fp1 = compute_normalized_fingerprint(
        cve="CVE-2023-1000", package_name="axios", title="Axios SSRF"
    )
    fp2 = compute_normalized_fingerprint(
        cve="CVE-2023-1000", package_name="axios", title="Axios SSRF"
    )
    f1 = NormalizedFinding(
        title="Axios SSRF",
        description="npm-audit report",
        severity=Severity.HIGH,
        confidence=0.70,
        scanner_name="npm-audit",
        cve="CVE-2023-1000",
        package_name="axios",
        normalized_fingerprint=fp1,
    )
    f2 = NormalizedFinding(
        title="Axios SSRF",
        description="Trivy report",
        severity=Severity.HIGH,
        confidence=0.70,
        scanner_name="trivy",
        cve="CVE-2023-1000",
        package_name="axios",
        normalized_fingerprint=fp2,
    )
    deduped = deduplicate_findings([f1, f2])
    assert len(deduped) == 2

    groups = correlate_findings(deduped, scan_id="scan-3")
    assert len(groups) == 1
    assert groups[0].evidence_level == EvidenceLevel.CORROBORATED_STATIC
    assert groups[0].canonical_cve == "CVE-2023-1000"
    assert len(groups[0].findings) == 2


def test_4_same_scanner_same_cve_package_repeated():
    fp = compute_normalized_fingerprint(
        cve="CVE-2022-40897", package_name="setuptools", title="ReDoS"
    )
    f1 = NormalizedFinding(
        title="ReDoS in setuptools",
        description="pip-audit 1",
        severity=Severity.MEDIUM,
        confidence=0.70,
        scanner_name="pip-audit",
        cve="CVE-2022-40897",
        package_name="setuptools",
        normalized_fingerprint=fp,
    )
    f2 = NormalizedFinding(
        title="ReDoS in setuptools",
        description="pip-audit 2",
        severity=Severity.MEDIUM,
        confidence=0.70,
        scanner_name="pip-audit",
        cve="CVE-2022-40897",
        package_name="setuptools",
        normalized_fingerprint=fp,
    )
    deduped = deduplicate_findings([f1, f2])
    assert len(deduped) == 1
    assert deduped[0].evidence_level == EvidenceLevel.SINGLE_SOURCE
    assert deduped[0].confidence == 0.70

    groups = correlate_findings(deduped, scan_id="scan-4")
    assert len(groups) == 1
    assert groups[0].evidence_level == EvidenceLevel.SINGLE_SOURCE
    assert len(groups[0].findings) == 1


def test_5_three_results_semgrep_duplicate_and_codeql():
    fp = compute_normalized_fingerprint(
        cwe="CWE-78", file_path="app/exec.py", title="cmd-injection"
    )
    f1 = NormalizedFinding(
        title="cmd-injection",
        description="Semgrep duplicate 1",
        severity=Severity.CRITICAL,
        confidence=0.50,
        scanner_name="semgrep",
        cwe="CWE-78",
        file_path="app/exec.py",
        normalized_fingerprint=fp,
    )
    f2 = NormalizedFinding(
        title="cmd-injection",
        description="Semgrep duplicate 2",
        severity=Severity.CRITICAL,
        confidence=0.50,
        scanner_name="semgrep",
        cwe="CWE-78",
        file_path="app/exec.py",
        normalized_fingerprint=fp,
    )
    f3 = NormalizedFinding(
        title="cmd-injection",
        description="CodeQL detection",
        severity=Severity.CRITICAL,
        confidence=0.70,
        scanner_name="codeql",
        cwe="CWE-78",
        file_path="app/exec.py",
        normalized_fingerprint=fp,
    )
    deduped = deduplicate_findings([f1, f2, f3])
    assert len(deduped) == 2
    scanners_after_dedup = {f.scanner_name for f in deduped}
    assert scanners_after_dedup == {"semgrep", "codeql"}

    groups = correlate_findings(deduped, scan_id="scan-5")
    assert len(groups) == 1
    assert groups[0].evidence_level == EvidenceLevel.CORROBORATED_STATIC
    assert len(groups[0].findings) == 2


def test_6_independent_findings():
    f1 = NormalizedFinding(
        title="sql-injection",
        description="Semgrep SQLi",
        severity=Severity.HIGH,
        confidence=0.50,
        scanner_name="semgrep",
        cwe="CWE-89",
        file_path="app/db.py",
        line_start=10,
        normalized_fingerprint="fp1",
    )
    f2 = NormalizedFinding(
        title="command-injection",
        description="CodeQL CmdExec",
        severity=Severity.CRITICAL,
        confidence=0.70,
        scanner_name="codeql",
        cwe="CWE-78",
        file_path="app/utils.py",
        line_start=50,
        normalized_fingerprint="fp2",
    )
    deduped = deduplicate_findings([f1, f2])
    assert len(deduped) == 2

    groups = correlate_findings(deduped, scan_id="scan-6")
    assert len(groups) == 2
    assert all(g.evidence_level == EvidenceLevel.SINGLE_SOURCE for g in groups)
    assert all(len(g.findings) == 1 for g in groups)


def test_7_single_scanner_group_never_corroborated():
    f1 = NormalizedFinding(
        title="rule-1",
        description="Semgrep finding 1",
        severity=Severity.MEDIUM,
        confidence=0.50,
        scanner_name="semgrep",
        cwe="CWE-79",
        file_path="templates/home.html",
        line_start=10,
        normalized_fingerprint="fp1",
    )
    f2 = NormalizedFinding(
        title="rule-2",
        description="Semgrep finding 2",
        severity=Severity.MEDIUM,
        confidence=0.50,
        scanner_name="semgrep",
        cwe="CWE-79",
        file_path="templates/home.html",
        line_start=12,
        normalized_fingerprint="fp2",
    )
    groups = correlate_findings([f1, f2], scan_id="scan-7")
    assert len(groups) == 1
    assert groups[0].evidence_level == EvidenceLevel.SINGLE_SOURCE
    assert all(f.evidence_level == EvidenceLevel.SINGLE_SOURCE for f in groups[0].findings)


def test_8_finding_evidence_preserves_same_scanner_occurrences():
    fp = compute_normalized_fingerprint(cwe="CWE-89", file_path="app/db.py", title="sqli")
    f1 = NormalizedFinding(
        title="sqli",
        description="Semgrep occ 1",
        severity=Severity.HIGH,
        confidence=0.50,
        scanner_name="semgrep",
        cwe="CWE-89",
        file_path="app/db.py",
        line_start=20,
        raw_data={"check_id": "sqli", "match": "line 20", "subproject": "backend"},
        normalized_fingerprint=fp,
    )
    f2 = NormalizedFinding(
        title="sqli",
        description="Semgrep occ 2",
        severity=Severity.HIGH,
        confidence=0.50,
        scanner_name="semgrep",
        cwe="CWE-89",
        file_path="app/db.py",
        line_start=25,
        raw_data={"check_id": "sqli", "match": "line 25", "subproject": "backend"},
        normalized_fingerprint=fp,
    )
    deduped = deduplicate_findings([f1, f2])
    assert len(deduped) == 1
    assert len(deduped[0].evidences) == 2
    matches = [ev["match"] for ev in deduped[0].evidences]
    assert "line 20" in matches
    assert "line 25" in matches


async def test_9_subproject_manifest_provenance_preserved(
    db_session: AsyncSession,
    tmp_path,
    npm_audit_json: str,
    pip_audit_json: str,
):
    proj_dir = tmp_path / "prov_test_repo"
    proj_dir.mkdir()
    (proj_dir / "frontend").mkdir()
    (proj_dir / "frontend" / "package.json").write_text('{"name": "frontend"}')
    (proj_dir / "backend").mkdir()
    (proj_dir / "backend" / "requirements.txt").write_text("flask==2.3.0")

    project = Project(name="Prov Project")
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
        elif "--version" in argv:
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

    evidences = (await db_session.execute(select(FindingEvidence))).scalars().all()
    assert len(evidences) > 0
    npm_evs = [e for e in evidences if e.scanner_name == "npm-audit"]
    assert len(npm_evs) > 0
    for ev in npm_evs:
        assert ev.raw_data.get("subproject") == "frontend"
        assert ev.raw_data.get("manifest") == "frontend/package.json"

    pip_evs = [e for e in evidences if e.scanner_name == "pip-audit"]
    assert len(pip_evs) > 0
    for ev in pip_evs:
        assert ev.raw_data.get("subproject") == "backend"
        assert ev.raw_data.get("manifest") == "backend/requirements.txt"


async def test_10_summary_differentiates_source_findings_and_correlation_groups(
    client: httpx.AsyncClient,
    db_session: AsyncSession,
    tmp_path,
):
    project = Project(name="Summary Test Project")
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

    group = CorrelationGroup(
        scan_id=scan.id,
        canonical_title="Corroborated High Vuln",
        canonical_cwe="CWE-89",
        severity=Severity.HIGH,
        confidence=0.90,
        evidence_level=EvidenceLevel.CORROBORATED_STATIC,
        status=FindingStatus.OPEN,
    )
    db_session.add(group)
    await db_session.flush()

    f1 = Finding(
        scan_id=scan.id,
        scanner_name="semgrep",
        title="SQL Injection in auth",
        severity=Severity.HIGH,
        confidence=0.70,
        evidence_level=EvidenceLevel.CORROBORATED_STATIC,
        correlation_group_id=group.id,
        cwe="CWE-89",
        file_path="app/auth.py",
        raw_fingerprint="fp1",
        normalized_fingerprint="norm1",
    )
    f2 = Finding(
        scan_id=scan.id,
        scanner_name="codeql",
        title="SQL Injection in auth query",
        severity=Severity.HIGH,
        confidence=0.85,
        evidence_level=EvidenceLevel.CORROBORATED_STATIC,
        correlation_group_id=group.id,
        cwe="CWE-89",
        file_path="app/auth.py",
        raw_fingerprint="fp2",
        normalized_fingerprint="norm2",
    )
    db_session.add_all([f1, f2])
    await db_session.commit()

    ev_res = await client.get(f"/api/scans/{scan.id}/evidence-summary")
    assert ev_res.status_code == 200
    ev_data = ev_res.json()
    assert ev_data["total_findings"] == 2
    assert ev_data["total_correlations"] == 1
    assert ev_data["corroborated_static_count"] == 2
    assert ev_data["single_source_count"] == 0

    sum_res = await client.get(f"/api/scans/{scan.id}/summary")
    assert sum_res.status_code == 200
    sum_data = sum_res.json()
    assert sum_data["totals"]["high"] == 2
    assert sum_data["correlated_totals"]["high"] == 1


def test_over_correlation_prevention():
    f_sqli = NormalizedFinding(
        title="SQL Injection",
        description="SQL injection vulnerability in query",
        severity=Severity.HIGH,
        confidence=0.70,
        scanner_name="semgrep",
        cwe="CWE-89",
        file_path="app/routes.py",
        line_start=20,
        normalized_fingerprint="sqli_fp",
    )
    f_cmd = NormalizedFinding(
        title="Command Injection",
        description="Command injection in os.system",
        severity=Severity.CRITICAL,
        confidence=0.70,
        scanner_name="codeql",
        cwe="CWE-78",
        file_path="app/routes.py",
        line_start=22,
        normalized_fingerprint="cmd_fp",
    )
    assert not are_findings_correlated(f_sqli, f_cmd)

    f_xss = NormalizedFinding(
        title="Reflected XSS",
        description="XSS in template rendering",
        severity=Severity.MEDIUM,
        confidence=0.60,
        scanner_name="semgrep",
        cwe="CWE-79",
        file_path="app/views.py",
        line_start=30,
        normalized_fingerprint="xss_fp",
    )
    f_ssrf = NormalizedFinding(
        title="SSRF Request",
        description="Server-Side Request Forgery",
        severity=Severity.HIGH,
        confidence=0.70,
        scanner_name="codeql",
        cwe="CWE-918",
        file_path="app/views.py",
        line_start=31,
        normalized_fingerprint="ssrf_fp",
    )
    assert not are_findings_correlated(f_xss, f_ssrf)

    f_traversal = NormalizedFinding(
        title="Directory Traversal",
        description="Path traversal in file reader",
        severity=Severity.HIGH,
        confidence=0.65,
        scanner_name="semgrep",
        cwe="CWE-22",
        file_path="app/files.py",
        line_start=40,
        normalized_fingerprint="trav_fp",
    )
    f_secret = NormalizedFinding(
        title="Hardcoded Secret Key",
        description="Secret API key exposed in code",
        severity=Severity.MEDIUM,
        confidence=0.80,
        scanner_name="codeql",
        cwe="CWE-798",
        file_path="app/files.py",
        line_start=41,
        normalized_fingerprint="secret_fp",
    )
    assert not are_findings_correlated(f_traversal, f_secret)
