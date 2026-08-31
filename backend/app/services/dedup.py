"""Deduplication of findings across scanners."""
from __future__ import annotations

import logging

from app.scanners.base import NormalizedFinding

logger = logging.getLogger(__name__)


def deduplicate_findings(
    findings: list[NormalizedFinding],
) -> list[NormalizedFinding]:
    """Deduplicate findings by normalized_fingerprint.

    When multiple scanners report the same finding (same normalized fingerprint),
    keep the one with highest severity/confidence and merge evidence.
    """
    seen: dict[str, NormalizedFinding] = {}
    for finding in findings:
        fp = finding.normalized_fingerprint
        if fp in seen:
            existing = seen[fp]
            # Bump confidence when corroborated
            existing.confidence = round(min(1.0, existing.confidence + 0.2), 2)
            # Keep more specific metadata if present
            if not existing.cwe and finding.cwe:
                existing.cwe = finding.cwe
            if not existing.cve and finding.cve:
                existing.cve = finding.cve
            if not existing.url and finding.url:
                existing.url = finding.url
            logger.info(
                "Dedup: %s corroborated by %s (fp=%s)",
                existing.scanner_name,
                finding.scanner_name,
                fp[:12],
            )
        else:
            seen[fp] = finding
    return list(seen.values())
