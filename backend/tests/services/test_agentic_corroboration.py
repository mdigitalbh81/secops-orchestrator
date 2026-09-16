"""Unit tests for Mantis agentic corroboration policy (PR20)."""

from __future__ import annotations

from typing import Any

import pytest

from app.models.enums import EvidenceLevel, FindingStatus, Severity
from app.scanners.base import NormalizedFinding
from app.services.agentic_corroboration import (
    POLICY_VERSION,
    CorroborationDecision,
    MantisCorroborationCandidate,
    apply_mantis_corroboration,
    evaluate_mantis_corroboration,
    normalize_cve,
    normalize_cwe,
    normalize_path,
)
from app.services.correlation import CorrelationGroupResult


def _make_deterministic(
    scanner_name: str = "semgrep",
    cwe: str | None = "CWE-79",
    cve: str | None = None,
    file_path: str | None = "app/views.py",
    line_start: int | None = 100,
    severity: Severity = Severity.HIGH,
    confidence: float = 0.55,
    status: FindingStatus = FindingStatus.OPEN,
    evidence_level: EvidenceLevel = EvidenceLevel.SINGLE_SOURCE,
    fingerprint: str = "fp_det_1",
) -> NormalizedFinding:
    return NormalizedFinding(
        title=f"Finding from {scanner_name}",
        description="Deterministic finding description",
        severity=severity,
        confidence=confidence,
        scanner_name=scanner_name,
        cwe=cwe,
        cve=cve,
        file_path=file_path,
        line_start=line_start,
        line_end=line_start + 5 if line_start else None,
        raw_fingerprint=fingerprint,
        normalized_fingerprint=fingerprint,
        evidence_level=evidence_level,
        status=status,
    )


def _make_mantis_candidate(
    finding_id: str = "mantis-vuln-1",
    cwe: str | None = "CWE-79",
    cve: str | None = None,
    file_path: str | None = "app/views.py",
    line_start: int | None = 103,
    confidence: float = 0.55,
    mantis_status: str = "VALID",
    mantis_status_explicit: bool = True,
    source_revision: str | None = "d13c93fb8e9779801711daea0d65fffa133c3b2d",
) -> MantisCorroborationCandidate:
    return MantisCorroborationCandidate(
        finding_id=finding_id,
        cwe=cwe,
        cve=cve,
        file_path=file_path,
        line_start=line_start,
        confidence=confidence,
        mantis_status=mantis_status,
        mantis_status_explicit=mantis_status_explicit,
        source_revision=source_revision,
    )


# ------------------------------------------------------------------
# Normalization helpers
# ------------------------------------------------------------------
def test_path_normalization() -> None:
    assert normalize_path("src/auth.py") == "src/auth.py"
    assert normalize_path("./src/auth.py") == "src/auth.py"
    assert normalize_path("/src/auth.py") == "src/auth.py"
    assert normalize_path(r"src\auth.py") == "src/auth.py"
    assert normalize_path("file:///src/auth.py") == "src/auth.py"
    assert normalize_path("backend/src/auth.py") == "backend/src/auth.py"
    assert normalize_path("backend/src/auth.py") != normalize_path("src/auth.py")
    assert normalize_path(None) is None
    assert normalize_path("") is None


def test_cwe_normalization() -> None:
    assert normalize_cwe("CWE-79") == "CWE-79"
    assert normalize_cwe("cwe-79") == "CWE-79"
    assert normalize_cwe("79") == "CWE-79"
    assert normalize_cwe("CWE/79") == "CWE-79"
    assert normalize_cwe("CWE-079") == "CWE-79"
    assert normalize_cwe(None) is None
    assert normalize_cwe("") is None
    assert normalize_cwe("OWASP-A1") == "OWASP-A1"


def test_cve_normalization() -> None:
    assert normalize_cve("cve-2023-1234") == "CVE-2023-1234"
    assert normalize_cve("  CVE-2023-1234  ") == "CVE-2023-1234"
    assert normalize_cve(None) is None
    assert normalize_cve("") is None


# ------------------------------------------------------------------
# Scanner Matrix (Section 10 & 32)
# ------------------------------------------------------------------
@pytest.mark.parametrize("scanner", ["semgrep", "codeql", "trivy", "npm-audit", "pip-audit"])
def test_eligible_scanners_promote(scanner: str) -> None:
    det = _make_deterministic(scanner_name=scanner)
    cand = _make_mantis_candidate()
    res = apply_mantis_corroboration([det], candidates=[cand])
    assert res.promotions_count == 1
    assert det.evidence_level == EvidenceLevel.CORROBORATED_STATIC


@pytest.mark.parametrize("scanner", ["ai-appsec", "zap", "nuclei", "mantis", "unknown-scanner"])
def test_ineligible_scanners_do_not_promote(scanner: str) -> None:
    det = _make_deterministic(scanner_name=scanner)
    cand = _make_mantis_candidate()
    res = apply_mantis_corroboration([det], candidates=[cand])
    assert res.promotions_count == 0
    assert det.evidence_level == EvidenceLevel.SINGLE_SOURCE


# ------------------------------------------------------------------
# Mantis Status Matrix (Section 12, 13, 30)
# ------------------------------------------------------------------
def test_explicit_valid_promotes() -> None:
    det = _make_deterministic()
    cand = _make_mantis_candidate(mantis_status="VALID", mantis_status_explicit=True)
    res = apply_mantis_corroboration([det], candidates=[cand])
    assert res.promotions_count == 1
    assert det.evidence_level == EvidenceLevel.CORROBORATED_STATIC


def test_default_omitted_valid_rejected() -> None:
    det = _make_deterministic()
    cand = _make_mantis_candidate(mantis_status="VALID", mantis_status_explicit=False)
    res = apply_mantis_corroboration([det], candidates=[cand])
    assert res.promotions_count == 0
    assert det.evidence_level == EvidenceLevel.SINGLE_SOURCE


@pytest.mark.parametrize(
    "status",
    [
        "PROVISIONALLY_VALID",
        "NEEDS_RESEARCH",
        "FALSE_POSITIVE",
        "FP",
        "DUPLICATE",
        "UNKNOWN",
        "",
        "SOMETHING_ELSE",
    ],
)
def test_non_valid_mantis_status_rejected(status: str) -> None:
    det = _make_deterministic()
    cand = _make_mantis_candidate(mantis_status=status, mantis_status_explicit=True, confidence=0.60)
    res = apply_mantis_corroboration([det], candidates=[cand])
    assert res.promotions_count == 0
    assert det.evidence_level == EvidenceLevel.SINGLE_SOURCE


# ------------------------------------------------------------------
# Confidence Matrix (Section 11, 12, 31)
# ------------------------------------------------------------------
def test_deterministic_confidence_boundary() -> None:
    cand = _make_mantis_candidate(confidence=0.55)

    # 0.49: ineligible
    det_low = _make_deterministic(confidence=0.49)
    res_low = apply_mantis_corroboration([det_low], candidates=[cand])
    assert res_low.promotions_count == 0
    assert det_low.evidence_level == EvidenceLevel.SINGLE_SOURCE

    # 0.50: eligible
    det_ok = _make_deterministic(confidence=0.50)
    res_ok = apply_mantis_corroboration([det_ok], candidates=[cand])
    assert res_ok.promotions_count == 1
    assert det_ok.evidence_level == EvidenceLevel.CORROBORATED_STATIC


def test_mantis_confidence_boundary() -> None:
    det = _make_deterministic(confidence=0.55)

    # 0.49: ineligible
    cand_low = _make_mantis_candidate(confidence=0.49)
    res_low = apply_mantis_corroboration([det], candidates=[cand_low])
    assert res_low.promotions_count == 0
    assert det.evidence_level == EvidenceLevel.SINGLE_SOURCE

    # 0.50: eligible
    cand_ok = _make_mantis_candidate(confidence=0.50)
    res_ok = apply_mantis_corroboration([det], candidates=[cand_ok])
    assert res_ok.promotions_count == 1
    assert det.evidence_level == EvidenceLevel.CORROBORATED_STATIC


# ------------------------------------------------------------------
# Location & Rule Matching (Section 14, 15, 16, 33)
# ------------------------------------------------------------------
def test_cwe_match_line_distance_boundaries() -> None:
    det = _make_deterministic(cwe="CWE-79", file_path="app/views.py", line_start=100)

    # Distance 0: YES
    c0 = _make_mantis_candidate(cwe="CWE-79", file_path="app/views.py", line_start=100)
    assert apply_mantis_corroboration([det], candidates=[c0]).promotions_count == 1
    det.evidence_level = EvidenceLevel.SINGLE_SOURCE
    det.evidences = []

    # Distance 5: YES
    c5 = _make_mantis_candidate(cwe="CWE-79", file_path="app/views.py", line_start=105)
    assert apply_mantis_corroboration([det], candidates=[c5]).promotions_count == 1
    det.evidence_level = EvidenceLevel.SINGLE_SOURCE
    det.evidences = []

    # Distance 6: NO
    c6 = _make_mantis_candidate(cwe="CWE-79", file_path="app/views.py", line_start=106)
    assert apply_mantis_corroboration([det], candidates=[c6]).promotions_count == 0
    assert det.evidence_level == EvidenceLevel.SINGLE_SOURCE


def test_cve_match_line_distance_boundaries() -> None:
    det = _make_deterministic(cwe=None, cve="CVE-2023-9999", file_path="app/views.py", line_start=50)

    # Distance 3: YES
    c3 = _make_mantis_candidate(cwe=None, cve="CVE-2023-9999", file_path="app/views.py", line_start=53)
    res = apply_mantis_corroboration([det], candidates=[c3])
    assert res.promotions_count == 1
    assert det.evidence_level == EvidenceLevel.CORROBORATED_STATIC
    assert det.evidences[-1]["match_rule"] == "cve_file_line"
    assert det.evidences[-1]["line_distance"] == 3


def test_different_cwe_same_file_line_no_promotion() -> None:
    det = _make_deterministic(cwe="CWE-79", file_path="app/views.py", line_start=100)
    cand = _make_mantis_candidate(cwe="CWE-89", file_path="app/views.py", line_start=100)
    assert apply_mantis_corroboration([det], candidates=[cand]).promotions_count == 0


def test_same_cwe_different_file_no_promotion() -> None:
    det = _make_deterministic(cwe="CWE-79", file_path="app/views.py", line_start=100)
    cand = _make_mantis_candidate(cwe="CWE-79", file_path="app/other.py", line_start=100)
    assert apply_mantis_corroboration([det], candidates=[cand]).promotions_count == 0


def test_missing_line_in_deterministic_no_promotion() -> None:
    det = _make_deterministic(cwe="CWE-79", file_path="app/views.py", line_start=None)
    cand = _make_mantis_candidate(cwe="CWE-79", file_path="app/views.py", line_start=100)
    assert apply_mantis_corroboration([det], candidates=[cand]).promotions_count == 0


def test_missing_line_in_mantis_no_promotion() -> None:
    det = _make_deterministic(cwe="CWE-79", file_path="app/views.py", line_start=100)
    cand = _make_mantis_candidate(cwe="CWE-79", file_path="app/views.py", line_start=None)
    assert apply_mantis_corroboration([det], candidates=[cand]).promotions_count == 0


def test_dependency_match_without_location_no_promotion() -> None:
    det = _make_deterministic(cve="CVE-2023-1234", file_path=None, line_start=None)
    cand = _make_mantis_candidate(cve="CVE-2023-1234", file_path=None, line_start=None)
    assert apply_mantis_corroboration([det], candidates=[cand]).promotions_count == 0


def test_similar_title_only_no_promotion() -> None:
    det = _make_deterministic(cwe=None, cve=None, file_path="app/views.py", line_start=100)
    cand = _make_mantis_candidate(cwe=None, cve=None, file_path="app/views.py", line_start=100)
    assert apply_mantis_corroboration([det], candidates=[cand]).promotions_count == 0


def test_path_no_fuzzy_suffix_match() -> None:
    det = _make_deterministic(cwe="CWE-79", file_path="backend/src/auth.py", line_start=10)
    cand = _make_mantis_candidate(cwe="CWE-79", file_path="src/auth.py", line_start=10)
    assert apply_mantis_corroboration([det], candidates=[cand]).promotions_count == 0


# ------------------------------------------------------------------
# Ambiguity (Section 17 & 34)
# ------------------------------------------------------------------
def test_ambiguous_match_promotes_zero() -> None:
    det1 = _make_deterministic(line_start=100, fingerprint="fp_1")
    det2 = _make_deterministic(line_start=102, fingerprint="fp_2")
    cand = _make_mantis_candidate(line_start=101)  # within 5 of both det1 and det2

    res = apply_mantis_corroboration([det1, det2], candidates=[cand])
    assert res.promotions_count == 0
    assert res.ambiguous_count == 1
    assert det1.evidence_level == EvidenceLevel.SINGLE_SOURCE
    assert det2.evidence_level == EvidenceLevel.SINGLE_SOURCE


# ------------------------------------------------------------------
# Human Dispositions (Section 11 & 35)
# ------------------------------------------------------------------
@pytest.mark.parametrize(
    "disp_status",
    [
        FindingStatus.FALSE_POSITIVE,
        FindingStatus.ACCEPTED_RISK,
        FindingStatus.ACCEPTED_BY_DESIGN,
        FindingStatus.FIXED,
    ],
)
def test_human_disposition_not_overridden_by_mantis(disp_status: FindingStatus) -> None:
    det = _make_deterministic(status=disp_status)
    cand = _make_mantis_candidate()
    res = apply_mantis_corroboration([det], candidates=[cand])
    assert res.promotions_count == 0
    assert det.evidence_level == EvidenceLevel.SINGLE_SOURCE
    assert det.status == disp_status


# ------------------------------------------------------------------
# Existing Corroboration & Runtime Validation (Section 11, 23, 36)
# ------------------------------------------------------------------
def test_existing_corroborated_static_not_repromoted() -> None:
    det = _make_deterministic(evidence_level=EvidenceLevel.CORROBORATED_STATIC)
    cand = _make_mantis_candidate()
    res = apply_mantis_corroboration([det], candidates=[cand])
    assert res.promotions_count == 0
    assert det.evidence_level == EvidenceLevel.CORROBORATED_STATIC


def test_existing_runtime_validated_not_downgraded() -> None:
    det = _make_deterministic(evidence_level=EvidenceLevel.RUNTIME_VALIDATED)
    cand = _make_mantis_candidate()
    res = apply_mantis_corroboration([det], candidates=[cand])
    assert res.promotions_count == 0
    assert det.evidence_level == EvidenceLevel.RUNTIME_VALIDATED


# ------------------------------------------------------------------
# Group Synchronization (Section 19, 37)
# ------------------------------------------------------------------
def test_group_synchronization() -> None:
    det = _make_deterministic(confidence=0.55, severity=Severity.HIGH)
    cg = CorrelationGroupResult(
        id="grp-1",
        scan_id="scan-1",
        canonical_title="XSS Title",
        canonical_cwe="CWE-79",
        canonical_cve=None,
        severity=Severity.HIGH,
        confidence=0.55,
        evidence_level=EvidenceLevel.SINGLE_SOURCE,
        status=FindingStatus.OPEN,
        remediation_recommendation=None,
        findings=[det],
    )
    cand = _make_mantis_candidate()
    res = apply_mantis_corroboration([det], correlation_groups=[cg], candidates=[cand])
    assert res.promotions_count == 1
    assert det.evidence_level == EvidenceLevel.CORROBORATED_STATIC
    assert cg.evidence_level == EvidenceLevel.CORROBORATED_STATIC
    # Severity and confidence must be unchanged
    assert det.severity == Severity.HIGH
    assert det.confidence == 0.55
    assert cg.severity == Severity.HIGH
    assert cg.confidence == 0.55


def test_group_runtime_validated_not_downgraded() -> None:
    det = _make_deterministic()
    cg = CorrelationGroupResult(
        id="grp-1",
        scan_id="scan-1",
        canonical_title="Title",
        canonical_cwe="CWE-79",
        canonical_cve=None,
        severity=Severity.HIGH,
        confidence=0.75,
        evidence_level=EvidenceLevel.RUNTIME_VALIDATED,
        status=FindingStatus.OPEN,
        remediation_recommendation=None,
        findings=[det],
    )
    cand = _make_mantis_candidate()
    apply_mantis_corroboration([det], correlation_groups=[cg], candidates=[cand])
    assert cg.evidence_level == EvidenceLevel.RUNTIME_VALIDATED


# ------------------------------------------------------------------
# Idempotence (Section 18 & 42)
# ------------------------------------------------------------------
def test_idempotence_repeated_execution() -> None:
    det = _make_deterministic()
    cand = _make_mantis_candidate()

    # Run 1
    res1 = apply_mantis_corroboration([det], candidates=[cand])
    assert res1.promotions_count == 1
    assert det.evidence_level == EvidenceLevel.CORROBORATED_STATIC
    assert len(det.evidences) == 1
    initial_confidence = det.confidence

    # Run 2 on same set
    res2 = apply_mantis_corroboration([det], candidates=[cand])
    assert res2.promotions_count == 0
    assert det.evidence_level == EvidenceLevel.CORROBORATED_STATIC
    assert len(det.evidences) == 1
    assert det.confidence == initial_confidence


# ------------------------------------------------------------------
# Sanitized FindingEvidence Provenance (Section 24)
# ------------------------------------------------------------------
def test_finding_evidence_keys() -> None:
    det = _make_deterministic()
    cand = _make_mantis_candidate()
    res = apply_mantis_corroboration([det], candidates=[cand])
    assert res.promotions_count == 1

    ev = det.evidences[-1]
    assert ev["source_agent"] == "mantis"
    assert ev["policy_version"] == POLICY_VERSION
    assert ev["advisory_finding_id"] == cand.finding_id
    assert ev["match_rule"] == "cwe_file_line"
    assert ev["line_distance"] == 3
    assert ev["mantis_status"] == "VALID"
    assert ev["mantis_confidence"] == 0.55
    assert ev["promotion_from"] == "SINGLE_SOURCE"
    assert ev["promotion_to"] == "CORROBORATED_STATIC"
    assert ev["risk_gate_influence"] is True
    assert ev["source_revision"] == cand.source_revision


# ------------------------------------------------------------------
# Severity Authoritative (Section 40)
# ------------------------------------------------------------------
def test_deterministic_severity_authoritative() -> None:
    """Mantis severity cannot override deterministic severity."""
    det_high = _make_deterministic(severity=Severity.HIGH)
    cand = _make_mantis_candidate()
    res = apply_mantis_corroboration([det_high], candidates=[cand])
    assert res.promotions_count == 1
    assert det_high.severity == Severity.HIGH
    assert det_high.evidence_level == EvidenceLevel.CORROBORATED_STATIC


# ------------------------------------------------------------------
# Mutation Atomicity (Section 6)
# ------------------------------------------------------------------
def test_evaluation_phase_does_not_mutate() -> None:
    """FASE 1 evaluation must never mutate findings or correlation groups."""
    det1 = _make_deterministic(line_start=100, fingerprint="fp_1")
    det2 = _make_deterministic(line_start=200, fingerprint="fp_2")
    cand1 = _make_mantis_candidate(line_start=102)
    cand2 = _make_mantis_candidate(line_start=202)
    cg = CorrelationGroupResult(
        id="grp-1",
        scan_id="scan-1",
        canonical_title="Group Title",
        canonical_cwe="CWE-79",
        canonical_cve=None,
        severity=Severity.HIGH,
        confidence=0.55,
        evidence_level=EvidenceLevel.SINGLE_SOURCE,
        status=FindingStatus.OPEN,
        remediation_recommendation=None,
        findings=[det1, det2],
    )

    decisions, ambiguous_count = evaluate_mantis_corroboration(
        [det1, det2], [cand1, cand2]
    )
    assert len(decisions) == 2
    assert all(isinstance(d, CorroborationDecision) for d in decisions)
    assert ambiguous_count == 0
    # Both remain SINGLE_SOURCE
    assert det1.evidence_level == EvidenceLevel.SINGLE_SOURCE
    assert det2.evidence_level == EvidenceLevel.SINGLE_SOURCE
    # No policy evidence added
    assert len(det1.evidences) == 0
    assert len(det2.evidences) == 0
    # Groups unaltered
    assert cg.evidence_level == EvidenceLevel.SINGLE_SOURCE


def test_failure_during_evaluation_leaves_zero_mutations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failure during evaluation phase must leave zero mutations across all findings."""
    import app.services.agentic_corroboration as ac_mod

    det1 = _make_deterministic(line_start=100, fingerprint="fp_1")
    det2 = _make_deterministic(line_start=200, fingerprint="fp_2")
    cand1 = _make_mantis_candidate(line_start=102)
    cand2 = _make_mantis_candidate(line_start=202)
    cg = CorrelationGroupResult(
        id="grp-1",
        scan_id="scan-1",
        canonical_title="Group Title",
        canonical_cwe="CWE-79",
        canonical_cve=None,
        severity=Severity.HIGH,
        confidence=0.55,
        evidence_level=EvidenceLevel.SINGLE_SOURCE,
        status=FindingStatus.OPEN,
        remediation_recommendation=None,
        findings=[det1, det2],
    )

    orig_matches = ac_mod._matches_structural

    def fail_on_cand2(d: Any, c: Any) -> tuple[bool, str | None, int | None]:
        if c.line_start == 202:
            raise RuntimeError("synthetic evaluation failure on candidate 2")
        return orig_matches(d, c)

    monkeypatch.setattr(ac_mod, "_matches_structural", fail_on_cand2)

    with pytest.raises(RuntimeError, match="synthetic evaluation failure on candidate 2"):
        apply_mantis_corroboration(
            [det1, det2], correlation_groups=[cg], candidates=[cand1, cand2]
        )

    # Neither finding is promoted; both remain SINGLE_SOURCE (no partial mutation)
    assert det1.evidence_level == EvidenceLevel.SINGLE_SOURCE
    assert det2.evidence_level == EvidenceLevel.SINGLE_SOURCE
    assert len(det1.evidences) == 0
    assert len(det2.evidences) == 0
    assert cg.evidence_level == EvidenceLevel.SINGLE_SOURCE
