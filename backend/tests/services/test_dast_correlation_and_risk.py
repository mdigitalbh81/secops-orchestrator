from app.models.enums import EvidenceLevel, RiskGate, Severity
from app.scanners.base import (
    NormalizedFinding,
)
from app.services.confidence import adjust_confidence, compute_group_confidence
from app.services.correlation import are_findings_correlated, correlate_findings
from app.services.dedup import deduplicate_findings
from app.services.risk_engine import compute_risk_gate


def test_dast_finding_has_runtime_validated_evidence_level():
    finding = NormalizedFinding(
        title="SQL Injection",
        description="SQL injection runtime finding",
        severity=Severity.HIGH,
        confidence=0.75,
        scanner_name="zap",
        cwe="CWE-89",
        url="http://staging-app:3000/api/users",
        evidence_level=EvidenceLevel.RUNTIME_VALIDATED,
    )
    assert finding.evidence_level == EvidenceLevel.RUNTIME_VALIDATED


def test_static_and_dast_correlation_promotes_to_runtime_validated():
    # Semgrep static finding on SQL injection in app/api/users.py
    f_sast = NormalizedFinding(
        title="python.django.security.injection.sql",
        description="SQL query formatted with user input",
        severity=Severity.HIGH,
        confidence=0.50,
        scanner_name="semgrep",
        cwe="CWE-89",
        file_path="app/api/users.py",
        line_start=25,
        line_end=25,
        evidence_level=EvidenceLevel.SINGLE_SOURCE,
    )

    # ZAP runtime finding on endpoint /api/users with CWE-89
    f_dast = NormalizedFinding(
        title="SQL Injection",
        description="SQL Injection validated at runtime on /api/users",
        severity=Severity.HIGH,
        confidence=0.75,
        scanner_name="zap",
        cwe="CWE-89",
        url="http://staging-app:3000/api/users",
        evidence_level=EvidenceLevel.RUNTIME_VALIDATED,
    )

    assert are_findings_correlated(f_sast, f_dast) is True

    groups = correlate_findings([f_sast, f_dast], scan_id="test-scan-1")
    assert len(groups) == 1
    group = groups[0]
    assert group.evidence_level == EvidenceLevel.RUNTIME_VALIDATED
    assert len(group.findings) == 2
    # Both findings in the validated group have RUNTIME_VALIDATED
    for f in group.findings:
        assert f.evidence_level == EvidenceLevel.RUNTIME_VALIDATED

    # Risk gate on this group should be BLOCKED (High + RUNTIME_VALIDATED)
    adjusted = adjust_confidence([f_sast, f_dast])
    gate = compute_risk_gate(adjusted)
    assert gate == RiskGate.BLOCKED


def test_two_findings_same_dast_scanner_no_false_corroboration():
    # Two distinct alerts from ZAP
    f1 = NormalizedFinding(
        title="X-Frame-Options Header Not Set",
        description="Missing header",
        severity=Severity.LOW,
        confidence=0.65,
        scanner_name="zap",
        cwe="CWE-1021",
        url="http://staging-app:3000/page1",
        evidence_level=EvidenceLevel.RUNTIME_VALIDATED,
    )
    f2 = NormalizedFinding(
        title="X-Content-Type-Options Header Missing",
        description="Missing header",
        severity=Severity.LOW,
        confidence=0.65,
        scanner_name="zap",
        cwe="CWE-16",
        url="http://staging-app:3000/page2",
        evidence_level=EvidenceLevel.RUNTIME_VALIDATED,
    )

    # They should not correlate because CWEs and URLs are different
    assert are_findings_correlated(f1, f2) is False

    groups = correlate_findings([f1, f2], scan_id="test-scan-2")
    assert len(groups) == 2

    # If duplicate alerts from ZAP on same endpoint:
    f1_dup = NormalizedFinding(
        title="X-Frame-Options Header Not Set",
        description="Missing header again",
        severity=Severity.LOW,
        confidence=0.65,
        scanner_name="zap",
        cwe="CWE-1021",
        url="http://staging-app:3000/page1",
        evidence_level=EvidenceLevel.RUNTIME_VALIDATED,
    )
    # Dedup combines them
    deduped = deduplicate_findings([f1, f1_dup])
    assert len(deduped) == 1
    assert deduped[0].evidence_level == EvidenceLevel.RUNTIME_VALIDATED

    # Same scanner alone gets 0 multi-scanner confidence bonus
    conf = compute_group_confidence([f1, f1_dup])
    assert conf == 0.65  # No +0.20 multi-scanner bonus!


def test_zero_findings_dast_evaluates_to_pass():
    gate = compute_risk_gate([])
    assert gate == RiskGate.PASS


def test_nuclei_cve_correlation_with_trivy():
    f_trivy = NormalizedFinding(
        title="CVE-2021-41773",
        description="Apache HTTP Server Path Traversal",
        severity=Severity.CRITICAL,
        confidence=0.70,
        scanner_name="trivy",
        cve="CVE-2021-41773",
        package_name="apache2",
        installed_version="2.4.49",
        evidence_level=EvidenceLevel.SINGLE_SOURCE,
    )
    f_nuclei = NormalizedFinding(
        title="Apache 2.4.49 - Path Traversal & Remote Code Execution",
        description="Matched CVE-2021-41773 at runtime",
        severity=Severity.CRITICAL,
        confidence=0.85,
        scanner_name="nuclei",
        cve="CVE-2021-41773",
        url="http://staging-app:3000/icons/.%2e/etc/passwd",
        evidence_level=EvidenceLevel.RUNTIME_VALIDATED,
    )

    assert are_findings_correlated(f_trivy, f_nuclei) is True

    groups = correlate_findings([f_trivy, f_nuclei], scan_id="test-scan-3")
    assert len(groups) == 1
    assert groups[0].evidence_level == EvidenceLevel.RUNTIME_VALIDATED
    assert groups[0].severity == Severity.CRITICAL
    assert groups[0].canonical_cve == "CVE-2021-41773"

    gate = compute_risk_gate([f_trivy, f_nuclei])
    assert gate == RiskGate.BLOCKED
