from app.models.enums import RiskGate, Severity
from app.scanners.base import NormalizedFinding
from app.services.risk_engine import compute_risk_gate


def _make_finding(severity: Severity, confidence: float) -> NormalizedFinding:
    return NormalizedFinding(
        title="Test",
        description="Test finding",
        severity=severity,
        confidence=confidence,
        scanner_name="test-scanner",
    )


def test_risk_gate_empty():
    assert compute_risk_gate([]) == RiskGate.PASS


def test_risk_gate_info_low():
    findings = [
        _make_finding(Severity.INFO, 1.0),
        _make_finding(Severity.LOW, 0.9),
    ]
    assert compute_risk_gate(findings) == RiskGate.PASS


def test_risk_gate_medium():
    findings = [
        _make_finding(Severity.MEDIUM, 0.5),
    ]
    assert compute_risk_gate(findings) == RiskGate.REVIEW


def test_risk_gate_high_low_confidence():
    findings = [
        _make_finding(Severity.HIGH, 0.5),
    ]
    assert compute_risk_gate(findings) == RiskGate.REVIEW


def test_risk_gate_high_high_confidence():
    findings = [
        _make_finding(Severity.HIGH, 0.7),
    ]
    assert compute_risk_gate(findings) == RiskGate.BLOCKED


def test_risk_gate_critical():
    findings = [
        _make_finding(Severity.CRITICAL, 0.5),
    ]
    assert compute_risk_gate(findings) == RiskGate.BLOCKED
