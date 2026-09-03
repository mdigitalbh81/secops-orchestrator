"""Confidence scoring engine v2.

Evaluates finding and correlation confidence deterministically based on
scanner source reliability, identifier specificity (CVE/CWE), and cross-tool corroboration.
"""

from __future__ import annotations

from app.models.enums import EvidenceLevel
from app.scanners.base import NormalizedFinding

BASE_SCANNER_CONFIDENCE = {
    "codeql": 0.70,
    "semgrep": 0.50,
    "npm-audit": 0.70,
    "pip-audit": 0.70,
    "trivy": 0.70,
    "ai-appsec": 0.45,
}


def adjust_confidence(findings: list[NormalizedFinding]) -> list[NormalizedFinding]:
    """Adjust confidence across findings based on evidence quality and corroboration.

    Rules:
    - CVE-based finding: +0.20 boost
    - Corroborated static finding: +0.20 boost (if not already boosted)
    - Cap at 1.0
    """
    for f in findings:
        boost = 0.0
        if f.cve or f.evidence_level == EvidenceLevel.CORROBORATED_STATIC:
            boost += 0.20

        f.confidence = round(min(1.0, f.confidence + boost), 2)
    return findings


def compute_group_confidence(findings: list[NormalizedFinding]) -> float:
    """Compute consolidated confidence score for a correlation group."""
    if not findings:
        return 0.0

    distinct_scanners = {f.scanner_name for f in findings}
    max_single = max(f.confidence for f in findings)

    if len(distinct_scanners) >= 3:
        bonus = 0.30
    elif len(distinct_scanners) == 2:
        bonus = 0.20
    else:
        bonus = 0.0

    has_cve = any(f.cve for f in findings)
    if has_cve and len(distinct_scanners) >= 2:
        bonus += 0.05

    return round(min(1.0, max_single + bonus), 2)
