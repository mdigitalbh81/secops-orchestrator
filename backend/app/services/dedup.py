"""Deduplication of findings across scanners."""

from __future__ import annotations

import logging

from app.models.enums import EvidenceLevel, Severity
from app.scanners.base import NormalizedFinding

logger = logging.getLogger(__name__)

SEVERITY_RANKS = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
    Severity.UNKNOWN: 0,
}


def deduplicate_findings(
    findings: list[NormalizedFinding],
) -> list[NormalizedFinding]:
    """Deduplicate findings by normalized_fingerprint.

    When multiple scanners report the same exact finding (same normalized fingerprint),
    keep the most detailed metadata, bump confidence, and mark evidence level as CORROBORATED_STATIC.
    """
    seen: dict[str, NormalizedFinding] = {}
    for finding in findings:
        fp = finding.normalized_fingerprint
        if fp in seen:
            existing = seen[fp]
            # Bump confidence when corroborated
            existing.confidence = round(min(1.0, existing.confidence + 0.2), 2)
            existing.evidence_level = EvidenceLevel.CORROBORATED_STATIC

            # Keep higher severity if current is higher
            if SEVERITY_RANKS.get(finding.severity, 0) > SEVERITY_RANKS.get(existing.severity, 0):
                existing.severity = finding.severity

            # Keep more specific metadata if present
            if not existing.cwe and finding.cwe:
                existing.cwe = finding.cwe
            if not existing.cve and finding.cve:
                existing.cve = finding.cve
            if not existing.url and finding.url:
                existing.url = finding.url
            if not existing.file_path and finding.file_path:
                existing.file_path = finding.file_path
            if existing.line_start is None and finding.line_start is not None:
                existing.line_start = finding.line_start
                existing.line_end = finding.line_end
            logger.info(
                "Dedup: corroborated %s with %s (fp=%s)",
                existing.scanner_name,
                finding.scanner_name,
                fp[:12],
            )
        else:
            seen[fp] = finding

    return list(seen.values())
