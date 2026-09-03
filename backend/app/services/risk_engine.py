"""Risk gate policy engine.

Evaluates PASS / REVIEW / BLOCKED decisions deterministically based on
severity, confidence score, and evidence level.
"""

from __future__ import annotations

from app.models.enums import EvidenceLevel, RiskGate, Severity
from app.scanners.base import NormalizedFinding


def compute_risk_gate(findings: list[NormalizedFinding]) -> RiskGate:
    """Compute overall risk gate for a set of normalized findings.

    Deterministic Policy:
    - Any CRITICAL with confidence >= 0.50 -> BLOCKED
    - Any HIGH with CORROBORATED_STATIC evidence -> BLOCKED
    - Any HIGH with confidence >= 0.70 -> BLOCKED
    - Any HIGH with SINGLE_SOURCE and confidence < 0.70 -> REVIEW
    - Any MEDIUM -> REVIEW (if not BLOCKED)
    - LOW / INFO / UNKNOWN only -> PASS (if not BLOCKED or REVIEW)
    - No findings -> PASS
    """
    if not findings:
        return RiskGate.PASS

    gate = RiskGate.PASS

    for f in findings:
        if f.severity == Severity.CRITICAL and f.confidence >= 0.50:
            return RiskGate.BLOCKED

        if f.severity == Severity.HIGH:
            if f.evidence_level == EvidenceLevel.CORROBORATED_STATIC or f.confidence >= 0.70:
                return RiskGate.BLOCKED
            gate = RiskGate.REVIEW

        elif f.severity == Severity.MEDIUM and gate == RiskGate.PASS:
            gate = RiskGate.REVIEW

    return gate
