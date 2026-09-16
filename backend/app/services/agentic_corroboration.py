"""Agentic corroboration policy service (PR20).

Allows Google Mantis safe-analysis findings to corroborate existing
deterministic findings under strict, conservative structural matching rules.
Mantis findings themselves remain strictly advisory, SINGLE_SOURCE, and
risk gate ineligible. Only matching deterministic findings may have their
evidence_level promoted to CORROBORATED_STATIC.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from typing import Any

from app.models.enums import EvidenceLevel, FindingStatus

logger = logging.getLogger(__name__)

POLICY_VERSION = "mantis-static-corroboration-v1"

ELIGIBLE_DETERMINISTIC_SCANNERS: frozenset[str] = frozenset({
    "semgrep",
    "codeql",
    "trivy",
    "npm-audit",
    "pip-audit",
})

MAX_LINE_DISTANCE = 5
MIN_DETERMINISTIC_CONFIDENCE = 0.50
MIN_MANTIS_CONFIDENCE = 0.50


@dataclass(frozen=True)
class MantisCorroborationCandidate:
    """Typed lightweight representation of a persisted Mantis advisory finding."""

    finding_id: str
    cwe: str | None = None
    cve: str | None = None
    file_path: str | None = None
    line_start: int | None = None
    confidence: float = 0.45
    mantis_status: str = "VALID"
    mantis_status_explicit: bool = False
    source_revision: str | None = None


@dataclass(frozen=True)
class CorroborationDecision:
    """Internal planned decision for corroborating a deterministic finding."""

    target: Any
    candidate: MantisCorroborationCandidate
    match_rule: str | None
    line_distance: int | None
    evidence_payload: dict[str, Any]


@dataclass
class CorroborationResult:
    """Summary outcome of applying Mantis corroboration policy."""

    promotions_count: int = 0
    ambiguous_count: int = 0
    promoted_findings: list[Any] = field(default_factory=list)


def normalize_path(path: str | None) -> str | None:
    """Deterministically normalize file paths for exact structural comparison."""
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
    res = cleaned.rstrip("/")
    return res if res else None


def normalize_cwe(cwe: str | None) -> str | None:
   """Extract and normalize CWE identifier."""
   if not cwe:
       return None
   s = cwe.strip()
   if s.isdigit():
       return f"CWE-{int(s)}"
   match = re.search(r"cwe[/-]?(\d+)", s, re.IGNORECASE)
   return f"CWE-{int(match.group(1))}" if match else cwe.strip().upper()


def normalize_cve(cve: str | None) -> str | None:
    """Normalize CVE identifier."""
    if not cve:
        return None
    s = cve.strip().upper()
    return s if s else None


def _matches_structural(
    deterministic: Any,
    candidate: MantisCorroborationCandidate,
) -> tuple[bool, str | None, int | None]:
    """Check strict structural match between deterministic finding and Mantis candidate.

    Returns (is_match, rule_name, line_distance).
    Requires:
    1. Both file_path present and exact normalized match.
    2. Both line_start present and abs(line1 - line2) <= MAX_LINE_DISTANCE (5).
    3. Either:
       a. CWE match: both CWE present and normalized CWE equal.
       b. CVE match: both CVE present and normalized CVE equal.
    """
    d_path = normalize_path(getattr(deterministic, "file_path", None))
    m_path = normalize_path(candidate.file_path)
    if not d_path or not m_path or d_path != m_path:
        return False, None, None

    d_line = getattr(deterministic, "line_start", None)
    m_line = candidate.line_start
    if d_line is None or m_line is None:
        return False, None, None

    line_dist = abs(d_line - m_line)
    if line_dist > MAX_LINE_DISTANCE:
        return False, None, None

    # Check CWE
    d_cwe = normalize_cwe(getattr(deterministic, "cwe", None))
    m_cwe = normalize_cwe(candidate.cwe)
    if d_cwe is not None and m_cwe is not None and d_cwe == m_cwe:
        return True, "cwe_file_line", line_dist

    # Check CVE
    d_cve = normalize_cve(getattr(deterministic, "cve", None))
    m_cve = normalize_cve(candidate.cve)
    if d_cve is not None and m_cve is not None and d_cve == m_cve:
        return True, "cve_file_line", line_dist

    return False, None, None


def evaluate_mantis_corroboration(
    deterministic_findings: list[Any],
    candidates: list[MantisCorroborationCandidate] | None = None,
) -> tuple[list[CorroborationDecision], int]:
    """FASE 1 - EVALUATION / PLANNING: Evaluate candidates and deterministic findings.

    Calculates matches, rejects ambiguities, and constructs promotion decisions
    WITHOUT mutating evidence_level, evidences, or correlation groups.
    """
    if not deterministic_findings or not candidates:
        return [], 0

    # Filter eligible candidates: explicit VALID, confidence >= 0.50
    eligible_candidates: list[MantisCorroborationCandidate] = []
    for c in candidates:
        if (
            c.mantis_status == "VALID"
            and c.mantis_status_explicit is True
            and c.confidence >= MIN_MANTIS_CONFIDENCE
        ):
            eligible_candidates.append(c)

    if not eligible_candidates:
        return [], 0

    # Filter eligible deterministic findings:
    # scanner in allowlist, status == OPEN, evidence_level == SINGLE_SOURCE, confidence >= 0.50
    eligible_deterministic: list[Any] = []
    for f in deterministic_findings:
        scanner = getattr(f, "scanner_name", None)
        status = getattr(f, "status", None)
        if isinstance(status, FindingStatus):
            status_val = status
        else:
            try:
                status_val = FindingStatus(str(status))
            except ValueError:
                status_val = None

        ev_level = getattr(f, "evidence_level", None)
        if isinstance(ev_level, EvidenceLevel):
            ev_val = ev_level
        else:
            try:
                ev_val = EvidenceLevel(str(ev_level))
            except ValueError:
                ev_val = None

        conf = getattr(f, "confidence", 0.0)

        # Do not promote non-allowlisted scanners
        if scanner not in ELIGIBLE_DETERMINISTIC_SCANNERS:
            continue
        # Do not promote non-OPEN findings (human dispositions like FALSE_POSITIVE, ACCEPTED_RISK, etc.)
        if status_val != FindingStatus.OPEN:
            continue
        # Only promote SINGLE_SOURCE; if already CORROBORATED_STATIC or RUNTIME_VALIDATED, do not touch
        if ev_val != EvidenceLevel.SINGLE_SOURCE:
            continue
        # Confidence threshold >= 0.50 (no rounding up)
        if conf < MIN_DETERMINISTIC_CONFIDENCE:
            continue

        # Check idempotency: if already has evidence from this policy, skip
        existing_evidences = getattr(f, "evidences", None) or []
        already_promoted = False
        for ev in existing_evidences:
            if isinstance(ev, dict) and ev.get("policy_version") == POLICY_VERSION:
                already_promoted = True
                break
            if (
                hasattr(ev, "raw_data")
                and isinstance(ev.raw_data, dict)
                and ev.raw_data.get("policy_version") == POLICY_VERSION
            ):
                already_promoted = True
                break
        if already_promoted:
            continue

        eligible_deterministic.append(f)

    if not eligible_deterministic:
        return [], 0

    decisions: list[CorroborationDecision] = []
    planned_keys: set[tuple[str, str]] = set()
    ambiguous_count = 0

    # Match each eligible candidate against eligible deterministic findings
    for cand in eligible_candidates:
        matches = [
            d for d in eligible_deterministic
            if _matches_structural(d, cand)[0]
        ]
        if not matches:
            continue
        if len(matches) > 1:
            # Ambiguity: candidate matches multiple deterministic findings -> promote none
            logger.info(
                "Ambiguous Mantis corroboration candidate %s matched %d deterministic findings; skipping promotion.",
                cand.finding_id,
                len(matches),
            )
            ambiguous_count += 1
            continue

        target = matches[0]
        fp_key = (
            getattr(target, "scanner_name", ""),
            getattr(target, "normalized_fingerprint", ""),
        )

        # Idempotence / deduplication: promote at most once
        if fp_key in planned_keys:
            continue

        _, match_rule, line_dist = _matches_structural(target, cand)

        evidence_payload: dict[str, Any] = {
            "source_agent": "mantis",
            "policy_version": POLICY_VERSION,
            "advisory_finding_id": cand.finding_id,
            "match_rule": match_rule,
            "line_distance": line_dist,
            "mantis_status": cand.mantis_status,
            "mantis_confidence": cand.confidence,
            "promotion_from": EvidenceLevel.SINGLE_SOURCE.value,
            "promotion_to": EvidenceLevel.CORROBORATED_STATIC.value,
            "risk_gate_influence": True,
            "source_revision": cand.source_revision,
        }

        decisions.append(
            CorroborationDecision(
                target=target,
                candidate=cand,
                match_rule=match_rule,
                line_distance=line_dist,
                evidence_payload=evidence_payload,
            )
        )
        planned_keys.add(fp_key)

    return decisions, ambiguous_count


def apply_mantis_corroboration(
    deterministic_findings: list[Any],
    correlation_groups: list[Any] | None = None,
    candidates: list[MantisCorroborationCandidate] | None = None,
) -> CorroborationResult:
    """Evaluate and apply Mantis static corroboration policy.

    Phase 1: Evaluation / Planning (all-or-nothing, zero mutations).
    Phase 2: Apply promotions and sync correlation groups only after successful evaluation.
    """
    if not deterministic_findings or not candidates:
        return CorroborationResult()

    decisions, ambiguous_count = evaluate_mantis_corroboration(
        deterministic_findings=deterministic_findings,
        candidates=candidates,
    )

    # FASE 2 - APPLY (only after all evaluation completes with success)
    promoted_findings: list[Any] = []
    for decision in decisions:
        target = decision.target
        target.evidence_level = EvidenceLevel.CORROBORATED_STATIC
        if hasattr(target, "__tablename__") and target.__tablename__ == "findings":
            from app.models.finding import FindingEvidence

            ev_obj = FindingEvidence(
                finding_id=getattr(target, "id", ""),
                scanner_name="mantis",
                raw_data=decision.evidence_payload,
            )
            target.evidences.append(ev_obj)
        else:
            if getattr(target, "evidences", None) is None:
                target.evidences = []
            target.evidences.append(decision.evidence_payload)

        promoted_findings.append(target)

    # Synchronize correlation groups (Section 37)
    if correlation_groups and promoted_findings:
        promoted_ids = {id(f) for f in promoted_findings}
        for cg in correlation_groups:
            cg_findings = getattr(cg, "findings", []) or []
            if (
                any(id(f) in promoted_ids for f in cg_findings)
                and cg.evidence_level != EvidenceLevel.RUNTIME_VALIDATED
            ):
                cg.evidence_level = EvidenceLevel.CORROBORATED_STATIC

    return CorroborationResult(
        promotions_count=len(promoted_findings),
        ambiguous_count=ambiguous_count,
        promoted_findings=promoted_findings,
    )
