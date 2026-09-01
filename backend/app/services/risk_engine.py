"""Simple risk gate engine.

Determines PASS / REVIEW / BLOCKED based on finding severities and confidence.
"""
from __future__ import annotations

from app.models.enums import RiskGate, Severity
from app.scanners.base import NormalizedFinding


def compute_risk_gate(findings: list[NormalizedFinding]) -> RiskGate:
    """Compute the overall risk gate for a set of findings.

    Rules:
    - CRITICAL with confidence >= 0.5 -> BLOCKED
    - HIGH with confidence >= 0.7 -> BLOCKED
    - HIGH with confidence < 0.7 -> REVIEW
    - MEDIUM -> REVIEW
    - LOW/INFO only -> PASS
    - No findings -> PASS
    """
    if not findings:
        return RiskGate.PASS

    gate = RiskGate.PASS
    for f in findings:
        if f.severity == Severity.CRITICAL and f.confidence >= 0.5:
            return RiskGate.BLOCKED
        if f.severity == Severity.HIGH and f.confidence >= 0.7:
            return RiskGate.BLOCKED
        if f.severity == Severity.HIGH:
            gate = RiskGate.REVIEW
        if f.severity == Severity.MEDIUM and gate == RiskGate.PASS:
            gate = RiskGate.REVIEW
    return gate
