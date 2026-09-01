"""Confidence scoring for findings."""
from __future__ import annotations

from app.scanners.base import NormalizedFinding


def adjust_confidence(findings: list[NormalizedFinding]) -> list[NormalizedFinding]:
    """Adjust confidence based on evidence quality.

    Rules:
    - CVE-based finding: +0.2
    - Already corroborated (confidence > base): keep
    - Cap at 1.0
    """
    for f in findings:
        if f.cve:
            f.confidence = round(min(1.0, f.confidence + 0.2), 2)
    return findings
