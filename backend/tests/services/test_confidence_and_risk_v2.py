from __future__ import annotations

from app.models.enums import EvidenceLevel, RiskGate, Severity
from app.scanners.base import NormalizedFinding
from app.services.confidence import compute_group_confidence
from app.services.risk_engine import compute_risk_gate


def test_confidence_group_scoring():
    f1 = NormalizedFinding(
        title="SQL Injection",
        description="Semgrep",
        severity=Severity.HIGH,
        confidence=0.50,
        scanner_name="semgrep",
    )
    f2 = NormalizedFinding(
        title="SQL Injection",
        description="CodeQL",
        severity=Severity.HIGH,
        confidence=0.70,
        scanner_name="codeql",
    )
    conf = compute_group_confidence([f1, f2])
    assert conf >= 0.90


def test_risk_gate_critical_blocked():
    f = NormalizedFinding(
        title="Critical vuln",
        description="",
        severity=Severity.CRITICAL,
        confidence=0.50,
        scanner_name="semgrep",
    )
    assert compute_risk_gate([f]) == RiskGate.BLOCKED


def test_risk_gate_high_corroborated_blocked():
    f = NormalizedFinding(
        title="High vuln",
        description="",
        severity=Severity.HIGH,
        confidence=0.60,
        evidence_level=EvidenceLevel.CORROBORATED_STATIC,
        scanner_name="semgrep",
    )
    assert compute_risk_gate([f]) == RiskGate.BLOCKED


def test_risk_gate_high_single_source_low_confidence_review():
    f = NormalizedFinding(
        title="High vuln single source",
        description="",
        severity=Severity.HIGH,
        confidence=0.50,
        evidence_level=EvidenceLevel.SINGLE_SOURCE,
        scanner_name="semgrep",
    )
    assert compute_risk_gate([f]) == RiskGate.REVIEW


def test_risk_gate_high_single_source_high_confidence_blocked():
    f = NormalizedFinding(
        title="High vuln codeql",
        description="",
        severity=Severity.HIGH,
        confidence=0.70,
        evidence_level=EvidenceLevel.SINGLE_SOURCE,
        scanner_name="codeql",
    )
    assert compute_risk_gate([f]) == RiskGate.BLOCKED


def test_risk_gate_medium_review():
    f = NormalizedFinding(
        title="Medium vuln",
        description="",
        severity=Severity.MEDIUM,
        confidence=0.80,
        scanner_name="pip-audit",
    )
    assert compute_risk_gate([f]) == RiskGate.REVIEW


def test_risk_gate_low_pass():
    f = NormalizedFinding(
        title="Low vuln",
        description="",
        severity=Severity.LOW,
        confidence=0.90,
        scanner_name="trivy",
    )
    assert compute_risk_gate([f]) == RiskGate.PASS
