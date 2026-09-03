"""Intelligent cross-scanner correlation engine.

Groups related findings across SAST, SCA, and AI analyzers into unified CorrelationGroups
using deterministic identifier matching, source location proximity, and rule equivalence.
"""

from __future__ import annotations

import logging
import os
import re
import uuid
from dataclasses import dataclass, field

from app.models.enums import EvidenceLevel, FindingStatus, Severity
from app.scanners.base import NormalizedFinding
from app.services.confidence import compute_group_confidence

logger = logging.getLogger(__name__)

SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
    Severity.UNKNOWN,
]


@dataclass
class CorrelationGroupResult:
    id: str
    scan_id: str
    canonical_title: str
    canonical_cwe: str | None
    canonical_cve: str | None
    severity: Severity
    confidence: float
    evidence_level: EvidenceLevel
    status: FindingStatus
    remediation_recommendation: str | None
    findings: list[NormalizedFinding] = field(default_factory=list)


def _normalize_cwe(cwe: str | None) -> str | None:
    if not cwe:
        return None
    match = re.search(r"cwe[/-]?(\d+)", cwe, re.IGNORECASE)
    return f"CWE-{int(match.group(1))}" if match else cwe.strip().upper()


def _normalize_pkg(pkg: str | None) -> str | None:
    return pkg.strip().lower() if pkg else None


def _normalize_path(path: str | None) -> str | None:
    if not path:
        return None
    cleaned = path.strip().replace("\\", "/")
    if cleaned.startswith("file://"):
        cleaned = cleaned[7:]
    cleaned = os.path.normpath(cleaned).replace("\\", "/")
    while cleaned.startswith("./") or cleaned.startswith("/"):
        if cleaned.startswith("./"):
            cleaned = cleaned[2:]
        elif cleaned.startswith("/"):
            cleaned = cleaned[1:]
    return cleaned.rstrip("/")


def _paths_match(p1: str | None, p2: str | None) -> bool:
    norm1 = _normalize_path(p1)
    norm2 = _normalize_path(p2)
    if not norm1 or not norm2:
        return False
    return norm1 == norm2 or norm1.endswith("/" + norm2) or norm2.endswith("/" + norm1)


def are_findings_correlated(f1: NormalizedFinding, f2: NormalizedFinding) -> bool:
    """Determine if two findings describe the same security issue."""
    # 0. Exact normalized fingerprint match across scanners
    if (
        f1.normalized_fingerprint
        and f2.normalized_fingerprint
        and f1.normalized_fingerprint == f2.normalized_fingerprint
    ):
        return True

    # 1. Exact CVE match
    if f1.cve and f2.cve and f1.cve.strip().upper() == f2.cve.strip().upper():
        pkg1, pkg2 = _normalize_pkg(f1.package_name), _normalize_pkg(f2.package_name)
        if pkg1 and pkg2 and pkg1 == pkg2:
            return True
        if not pkg1 or not pkg2:
            return True

    # 2. Package vulnerability match (same package and same CVE or title)
    pkg1, pkg2 = _normalize_pkg(f1.package_name), _normalize_pkg(f2.package_name)
    if pkg1 and pkg2 and pkg1 == pkg2:
        if f1.cve and f2.cve and f1.cve.strip().upper() == f2.cve.strip().upper():
            return True
        # Same package and overlapping title
        if f1.title.lower() == f2.title.lower():
            return True

    # 3. Source code SAST / AI match: same file and same CWE with nearby line numbers
    cwe1, cwe2 = _normalize_cwe(f1.cwe), _normalize_cwe(f2.cwe)

    if _paths_match(f1.file_path, f2.file_path) and cwe1 and cwe2 and cwe1 == cwe2:
        # Check line proximity
        if f1.line_start is not None and f2.line_start is not None:
            if abs(f1.line_start - f2.line_start) <= 15:
                return True
        else:
            return True

    # 4. Same file and matching check title/vulnerability class
    if _paths_match(f1.file_path, f2.file_path):
        t1, t2 = f1.title.lower(), f2.title.lower()
        d1, d2 = (f1.description or "").lower(), (f2.description or "").lower()
        vuln_keywords = [
            ("sql", "sqli"),
            ("command", "os command", "rce", "exec"),
            ("xss", "cross-site scripting"),
            ("ssrf", "server-side request forgery"),
            ("traversal", "path traversal", "directory traversal"),
            ("deserialization", "unpickling", "unserialize"),
            ("hardcoded", "secret", "credential", "api key", "password"),
            ("idor", "broken access", "authorization"),
            ("jwt", "token"),
        ]
        if any(any(k in t1 or k in d1 for k in g) and any(k in t2 or k in d2 for k in g) for g in vuln_keywords):
            if f1.line_start is not None and f2.line_start is not None:
                if abs(f1.line_start - f2.line_start) <= 15:
                    return True
            else:
                return True

    return False


def correlate_findings(
    findings: list[NormalizedFinding], scan_id: str
) -> list[CorrelationGroupResult]:
    """Cluster normalized findings into correlation groups and update evidence levels."""
    if not findings:
        return []

    # Disjoint-set clustering
    groups: list[list[NormalizedFinding]] = []
    for finding in findings:
        matched_group = None
        for group in groups:
            if any(are_findings_correlated(finding, member) for member in group):
                matched_group = group
                break
        if matched_group is not None:
            matched_group.append(finding)
        else:
            groups.append([finding])

    results: list[CorrelationGroupResult] = []
    for group_findings in groups:
        group_id = str(uuid.uuid4())
        distinct_scanners = {f.scanner_name for f in group_findings}

        evidence_level = (
            EvidenceLevel.CORROBORATED_STATIC
            if len(distinct_scanners) >= 2
            else EvidenceLevel.SINGLE_SOURCE
        )

        # Update finding evidence levels
        for f in group_findings:
            f.evidence_level = evidence_level

        # Determine group severity (highest among findings)
        group_severity = Severity.UNKNOWN
        for sev in SEVERITY_ORDER:
            if any(f.severity == sev for f in group_findings):
                group_severity = sev
                break

        # Canonical title & metadata
        canonical_cwe = next((f.cwe for f in group_findings if f.cwe), None)
        canonical_cve = next((f.cve for f in group_findings if f.cve), None)

        # Pick best title (prefer descriptive SAST / advisory title)
        best_title = group_findings[0].title
        for f in group_findings:
            if f.scanner_name in ("codeql", "semgrep") and len(f.title) > len(best_title) or f.cve:
                best_title = f.title

        # Consolidated remediation
        remediation_parts: list[str] = []
        for f in group_findings:
            if f.fixed_version:
                remediation_parts.append(
                    f"Upgrade {f.package_name or 'package'} to version {f.fixed_version}."
                )
            if f.url:
                remediation_parts.append(f"Advisory: {f.url}")
        remediation_text = " ".join(dict.fromkeys(remediation_parts)) or None

        confidence = compute_group_confidence(group_findings)

        results.append(
            CorrelationGroupResult(
                id=group_id,
                scan_id=scan_id,
                canonical_title=best_title,
                canonical_cwe=_normalize_cwe(canonical_cwe),
                canonical_cve=canonical_cve,
                severity=group_severity,
                confidence=confidence,
                evidence_level=evidence_level,
                status=FindingStatus.OPEN,
                remediation_recommendation=remediation_text,
                findings=group_findings,
            )
        )

    return results
