from __future__ import annotations

from app.models.enums import EvidenceLevel, Severity
from app.scanners.base import NormalizedFinding
from app.services.correlation import correlate_findings


def test_correlate_semgrep_and_codeql_same_cwe_location():
    f1 = NormalizedFinding(
        title="SQL injection in user repository",
        description="Semgrep detected SQL injection vulnerability",
        severity=Severity.HIGH,
        confidence=0.50,
        scanner_name="semgrep",
        cwe="CWE-89",
        file_path="app/db/user_repo.py",
        line_start=25,
        line_end=26,
    )
    f2 = NormalizedFinding(
        title="SQL query built from user-controlled sources",
        description="CodeQL detected tainted dataflow to cursor.execute",
        severity=Severity.HIGH,
        confidence=0.70,
        scanner_name="codeql",
        cwe="CWE-89",
        file_path="app/db/user_repo.py",
        line_start=25,
        line_end=28,
    )

    groups = correlate_findings([f1, f2], scan_id="scan-123")
    assert len(groups) == 1
    g = groups[0]
    assert g.evidence_level == EvidenceLevel.CORROBORATED_STATIC
    assert g.canonical_cwe == "CWE-89"
    assert g.confidence >= 0.85
    assert len(g.findings) == 2
    assert f1.evidence_level == EvidenceLevel.CORROBORATED_STATIC
    assert f2.evidence_level == EvidenceLevel.CORROBORATED_STATIC


def test_correlate_npm_audit_and_trivy_same_cve_package():
    f1 = NormalizedFinding(
        title="CVE-2021-23337: lodash command injection",
        description="Command injection in lodash template",
        severity=Severity.HIGH,
        confidence=0.70,
        scanner_name="npm-audit",
        cve="CVE-2021-23337",
        package_name="lodash",
        installed_version="4.17.15",
        fixed_version="4.17.21",
    )
    f2 = NormalizedFinding(
        title="CVE-2021-23337",
        description="lodash vulnerable to Command Injection via template function",
        severity=Severity.HIGH,
        confidence=0.75,
        scanner_name="trivy",
        cve="CVE-2021-23337",
        package_name="lodash",
        installed_version="4.17.15",
        fixed_version="4.17.21",
    )

    groups = correlate_findings([f1, f2], scan_id="scan-456")
    assert len(groups) == 1
    g = groups[0]
    assert g.evidence_level == EvidenceLevel.CORROBORATED_STATIC
    assert g.canonical_cve == "CVE-2021-23337"
    assert len(g.findings) == 2


def test_correlate_pip_audit_and_trivy_same_cve():
    f1 = NormalizedFinding(
        title="CVE-2022-40897: setuptools ReDoS",
        description="setuptools vulnerable to ReDoS",
        severity=Severity.MEDIUM,
        confidence=0.70,
        scanner_name="pip-audit",
        cve="CVE-2022-40897",
        package_name="setuptools",
        installed_version="65.5.0",
        fixed_version="65.5.1",
    )
    f2 = NormalizedFinding(
        title="CVE-2022-40897",
        description="ReDoS vulnerability in setuptools package",
        severity=Severity.MEDIUM,
        confidence=0.70,
        scanner_name="trivy",
        cve="CVE-2022-40897",
        package_name="setuptools",
        installed_version="65.5.0",
        fixed_version="65.5.1",
    )

    groups = correlate_findings([f1, f2], scan_id="scan-789")
    assert len(groups) == 1
    assert groups[0].evidence_level == EvidenceLevel.CORROBORATED_STATIC


def test_single_source_finding():
    f1 = NormalizedFinding(
        title="Uncontrolled command line",
        description="CodeQL detected command injection",
        severity=Severity.CRITICAL,
        confidence=0.70,
        scanner_name="codeql",
        cwe="CWE-78",
        file_path="app/utils/exec.py",
        line_start=15,
    )
    groups = correlate_findings([f1], scan_id="scan-single")
    assert len(groups) == 1
    assert groups[0].evidence_level == EvidenceLevel.SINGLE_SOURCE
    assert groups[0].severity == Severity.CRITICAL


def test_no_over_dedup_different_files():
    f1 = NormalizedFinding(
        title="SQL injection in user repository",
        description="SQL injection in users",
        severity=Severity.HIGH,
        confidence=0.70,
        scanner_name="codeql",
        cwe="CWE-89",
        file_path="app/db/user_repo.py",
        line_start=20,
    )
    f2 = NormalizedFinding(
        title="SQL injection in orders repository",
        description="SQL injection in orders",
        severity=Severity.HIGH,
        confidence=0.70,
        scanner_name="codeql",
        cwe="CWE-89",
        file_path="app/db/order_repo.py",
        line_start=20,
    )
    groups = correlate_findings([f1, f2], scan_id="scan-diff")
    assert len(groups) == 2


def test_no_over_dedup_far_lines():
    f1 = NormalizedFinding(
        title="XSS vulnerability in header",
        description="Reflected XSS",
        severity=Severity.MEDIUM,
        confidence=0.50,
        scanner_name="semgrep",
        cwe="CWE-79",
        file_path="app/templates/render.py",
        line_start=10,
    )
    f2 = NormalizedFinding(
        title="XSS vulnerability in footer",
        description="DOM XSS",
        severity=Severity.MEDIUM,
        confidence=0.70,
        scanner_name="codeql",
        cwe="CWE-79",
    file_path="app/templates/render.py",
    line_start=150,
    )
    groups = correlate_findings([f1, f2], scan_id="scan-far")
    assert len(groups) == 2


def test_correlate_semgrep_absolute_codeql_relative_path() -> None:
    f1 = NormalizedFinding(
        title="python.sqlalchemy.security.audit.direct-sql-execution",
        description="Semgrep detected SQL injection vulnerability",
        severity=Severity.HIGH,
        confidence=0.50,
        scanner_name="semgrep",
        cwe="CWE-89",
        file_path="/tmp/secops-workspaces/phase2-sample-vulnerable/app.py",
        line_start=24,
        line_end=25,
    )
    f2 = NormalizedFinding(
        title="SQL query built from user-controlled sources",
        description="CodeQL detected tainted dataflow",
        severity=Severity.HIGH,
        confidence=0.70,
        scanner_name="codeql",
        cwe="CWE-89",
        file_path="app.py",
        line_start=24,
        line_end=27,
    )

    groups = correlate_findings([f1, f2], scan_id="scan-abs-rel")
    assert len(groups) == 1
    assert groups[0].evidence_level == EvidenceLevel.CORROBORATED_STATIC
    assert groups[0].confidence >= 0.85
    assert len(groups[0].findings) == 2


def test_correlate_vuln_keywords_without_exact_cwe() -> None:
    f1 = NormalizedFinding(
        title="Dangerous exec system call",
        description="User input passed directly to child_process exec",
        severity=Severity.CRITICAL,
        confidence=0.50,
        scanner_name="semgrep",
        cwe=None,
        file_path="/tmp/secops-workspaces/phase2-sample-vulnerable/server.js",
        line_start=18,
        line_end=19,
    )
    f2 = NormalizedFinding(
        title="Command injection in Node.js",
        description="CodeQL detected command line execution vulnerability",
        severity=Severity.CRITICAL,
        confidence=0.70,
        scanner_name="codeql",
        cwe="CWE-78",
        file_path="server.js",
        line_start=18,
        line_end=22,
    )

    groups = correlate_findings([f1, f2], scan_id="scan-kw")
    assert len(groups) == 1
    assert groups[0].evidence_level == EvidenceLevel.CORROBORATED_STATIC
    assert groups[0].confidence >= 0.85
    assert len(groups[0].findings) == 2
