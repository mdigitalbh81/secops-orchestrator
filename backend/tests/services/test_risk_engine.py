from app.models.enums import FindingStatus, RiskGate, Severity
from app.scanners.base import NormalizedFinding
from app.services.risk_engine import compute_risk_gate


def _make_finding(
    severity: Severity,
    confidence: float,
    status: FindingStatus = FindingStatus.OPEN,
) -> NormalizedFinding:
    return NormalizedFinding(
        title="Test",
        description="Test finding",
        severity=severity,
        confidence=confidence,
        scanner_name="test-scanner",
        status=status,
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
    findings = [_make_finding(Severity.MEDIUM, 0.5)]
    assert compute_risk_gate(findings) == RiskGate.REVIEW


def test_risk_gate_high_low_confidence():
    findings = [_make_finding(Severity.HIGH, 0.5)]
    assert compute_risk_gate(findings) == RiskGate.REVIEW


def test_risk_gate_high_high_confidence():
    findings = [_make_finding(Severity.HIGH, 0.7)]
    assert compute_risk_gate(findings) == RiskGate.BLOCKED


def test_risk_gate_critical():
    findings = [_make_finding(Severity.CRITICAL, 0.5)]
    assert compute_risk_gate(findings) == RiskGate.BLOCKED


def test_risk_gate_non_open_statuses_ignored():
    """Non-OPEN statuses (ACCEPTED_RISK, FALSE_POSITIVE, ACCEPTED_BY_DESIGN, FIXED) must never cause BLOCKED or REVIEW."""
    for non_open in [
        FindingStatus.ACCEPTED_RISK,
        FindingStatus.FALSE_POSITIVE,
        FindingStatus.ACCEPTED_BY_DESIGN,
        FindingStatus.FIXED,
    ]:
        critical = _make_finding(Severity.CRITICAL, 1.0, status=non_open)
        high = _make_finding(Severity.HIGH, 1.0, status=non_open)
        medium = _make_finding(Severity.MEDIUM, 1.0, status=non_open)
        assert compute_risk_gate([critical, high, medium]) == RiskGate.PASS


def test_risk_gate_mixed_open_and_suppressed():
    """Open findings drive the gate while suppressed critical/high are ignored."""
    suppressed_crit = _make_finding(Severity.CRITICAL, 1.0, status=FindingStatus.ACCEPTED_RISK)
    open_med = _make_finding(Severity.MEDIUM, 0.8, status=FindingStatus.OPEN)
    assert compute_risk_gate([suppressed_crit, open_med]) == RiskGate.REVIEW
