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
    seen: dict[tuple[str, str], NormalizedFinding] = {}
    for finding in findings:
        key = (finding.scanner_name, finding.normalized_fingerprint)
        if key in seen:
            existing = seen[key]
            finding_evidences = finding.evidences or ([finding.raw_data] if finding.raw_data else [])
            for ev in finding_evidences:
                if ev not in existing.evidences:
                    existing.evidences.append(ev)
            if SEVERITY_RANKS.get(finding.severity, 0) > SEVERITY_RANKS.get(existing.severity, 0):
                existing.severity = finding.severity
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
            if not existing.package_name and finding.package_name:
                existing.package_name = finding.package_name
            if not existing.installed_version and finding.installed_version:
                existing.installed_version = finding.installed_version
            if not existing.fixed_version and finding.fixed_version:
                existing.fixed_version = finding.fixed_version
            existing.confidence = max(existing.confidence, finding.confidence)
            existing.evidence_level = EvidenceLevel.SINGLE_SOURCE
            logger.info(
                "Dedup: consolidated same-scanner duplicate %s (fp=%s)",
                existing.scanner_name,
                key[1][:12],
            )
        else:
            if not finding.evidences and finding.raw_data:
                finding.evidences = [finding.raw_data]
            seen[key] = finding
    return list(seen.values())
