"""Risk gate policy engine.

Evaluates PASS / REVIEW / BLOCKED decisions deterministically based on
severity, confidence score, evidence level, and finding disposition status.
"""

from __future__ import annotations

from app.models.enums import EvidenceLevel, FindingStatus, RiskGate, Severity
from app.scanners.base import NormalizedFinding


def compute_risk_gate(findings: list[NormalizedFinding]) -> RiskGate:
    """Compute overall risk gate from a set of normalized findings.

    Only findings with FindingStatus.OPEN are actionable.
    Findings with FIXED, FALSE_POSITIVE, ACCEPTED_RISK, or ACCEPTED_BY_DESIGN
    are non-actionable and cannot cause REVIEW or BLOCKED.

    Deterministic Policy:
      - Any CRITICAL with confidence >= 0.50 -> BLOCKED
      - Any HIGH with CORROBORATED_STATIC or RUNTIME_VALIDATED evidence -> BLOCKED
      - Any HIGH with confidence >= 0.70 -> BLOCKED
      - Any HIGH with SINGLE_SOURCE and confidence < 0.70 -> REVIEW
      - Any MEDIUM -> REVIEW (if not BLOCKED)
      - LOW / INFO / UNKNOWN only -> PASS (if not BLOCKED or REVIEW)
      - Zero findings / non-actionable only -> PASS
    """
    if not findings:
        return RiskGate.PASS

    gate = RiskGate.PASS
    for f in findings:
        status = getattr(f, "status", FindingStatus.OPEN)
        if status != FindingStatus.OPEN:
            continue

        if f.severity == Severity.CRITICAL and f.confidence >= 0.50:
            return RiskGate.BLOCKED

        if f.severity == Severity.HIGH:
            if f.evidence_level in (
                EvidenceLevel.CORROBORATED_STATIC,
                EvidenceLevel.RUNTIME_VALIDATED,
            ) or f.confidence >= 0.70:
                return RiskGate.BLOCKED
            gate = RiskGate.REVIEW

        elif f.severity == Severity.MEDIUM and gate == RiskGate.PASS:
            gate = RiskGate.REVIEW

    return gate
