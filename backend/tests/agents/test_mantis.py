from __future__ import annotations

import json

import pytest

from app.agents.base import AgentCapability, AgentExecutionMode
from app.agents.mantis import (
    MantisAdapter,
)
from app.core.config import Settings, override_settings
from app.models.enums import EvidenceLevel, FindingStatus, Severity


def test_mantis_metadata_and_defaults() -> None:
    adapter = MantisAdapter()
    assert adapter.name == "mantis"
    assert adapter.UPSTREAM_REPO == "https://github.com/google/mantis"
    assert adapter.DEFAULT_REVISION == "d13c93fb8e9779801711daea0d65fffa133c3b2d"
    assert adapter.LICENSE == "Apache-2.0"
    assert adapter.INTEGRATION_TYPE == "skills_and_contracts"
    assert adapter.revision == "d13c93fb8e9779801711daea0d65fffa133c3b2d"
    assert not adapter.is_enabled()
    assert adapter.execution_mode == AgentExecutionMode.DISABLED


@pytest.mark.asyncio
async def test_mantis_is_available_returns_false() -> None:
    adapter = MantisAdapter()
    assert await adapter.is_available() is False


def test_mantis_safe_capabilities_only() -> None:
    adapter = MantisAdapter()
    assert adapter.is_safe_analysis_only()
    assert not adapter.allows_active_reproduction()
    assert not adapter.allows_patch_generation()
    assert adapter.has_capability(AgentCapability.REVIEW)
    assert adapter.has_capability(AgentCapability.ARCHITECTURE)
    assert adapter.has_capability(AgentCapability.THREAT_MODEL)
    assert adapter.has_capability(AgentCapability.PLAN)
    assert adapter.has_capability(AgentCapability.RESEARCH)
    assert adapter.has_capability(AgentCapability.CRITIC)
    assert adapter.has_capability(AgentCapability.REPORT)

    # Dangerous capabilities explicitly blocked
    assert not adapter.has_capability(AgentCapability.REPRODUCE)
    assert not adapter.has_capability(AgentCapability.CHAIN)
    assert not adapter.has_capability(AgentCapability.PATCH)


def test_mantis_enabled_via_settings() -> None:
    override_settings(
        Settings(
            mantis_enabled=True,
            mantis_revision="abcdef123456",
            mantis_execution_mode="sandbox",
        )
    )
    try:
        adapter = MantisAdapter()
        assert adapter.is_enabled() is True
        assert adapter.revision == "abcdef123456"
        assert adapter.execution_mode == AgentExecutionMode.SANDBOX
        # Still strictly blocked
        assert not adapter.allows_active_reproduction()
        assert not adapter.has_capability(AgentCapability.REPRODUCE)
    finally:
        override_settings(Settings())


def test_mantis_ingest_single_finding_and_evidence_safety() -> None:
    adapter = MantisAdapter()
    sample = {
        "id": "11111111-2222-3333-4444-555555555555",
        "title": "SQL Injection in User Profile Lookup",
        "description": "User input directly concatenated into SQL query.",
        "code_paths": ["app/db/users.py:42-50"],
        "impact": "Data exfiltration possible",
        "severity": "HIGH",
        "cwe": "CWE-89",
        "cve": "CVE-2024-12345",
        "mitigation": "Use parameterized queries.",
        "repro_status": "verified",  # Simulates LLM / Mantis claim
        "confidence": 0.85,  # Exceeds cap
    }

    findings = adapter.ingest_findings(sample)
    assert len(findings) == 1
    f = findings[0]

    assert f.title == "SQL Injection in User Profile Lookup"
    assert "Impact: Data exfiltration possible" in f.description
    assert "Mitigation: Use parameterized queries." in f.description
    assert f.severity == Severity.HIGH
    assert f.cwe == "CWE-89"
    assert f.cve == "CVE-2024-12345"
    assert f.file_path == "app/db/users.py"
    assert f.line_start == 42
    assert f.line_end == 50
    assert f.status == FindingStatus.OPEN
    assert f.scanner_name == "mantis"

    # CRITICAL: EvidenceLevel MUST NOT be RUNTIME_VALIDATED
    assert f.evidence_level == EvidenceLevel.SINGLE_SOURCE
    assert f.evidence_level != EvidenceLevel.RUNTIME_VALIDATED

    # Confidence must be capped to 0.60
    assert f.confidence == 0.60

    # Provenance tracking
    assert f.raw_data is not None
    assert f.raw_data["source_agent"] == "mantis"
    assert f.raw_data["source_revision"] == adapter.revision


def test_mantis_ingest_json_string_and_wrapped_findings() -> None:
    adapter = MantisAdapter()
    payload = {
        "findings": [
            {
                "title": "Insecure Direct Object Reference",
                "description": "No auth check on /documents/{id}",
                "code_paths": ["app/api/docs.py:100"],
                "severity": "CRITICAL",
                "cwe": "cwe-639",
                "confidence": 0.10,  # Below min cap
            },
            {
                "title": "Hardcoded JWT Secret",
                "description": "Static secret used for token signature",
                "file_path": "app/core/jwt.py",
                "line_start": 15,
                "severity": "MEDIUM",
                "cwe": "798",
            },
        ]
    }

    findings = adapter.ingest_findings(json.dumps(payload))
    assert len(findings) == 2

    f0 = findings[0]
    assert f0.title == "Insecure Direct Object Reference"
    assert f0.severity == Severity.CRITICAL
    assert f0.cwe == "CWE-639"
    assert f0.confidence == 0.20  # Clamped to min 0.20
    assert f0.file_path == "app/api/docs.py"
    assert f0.line_start == 100
    assert f0.line_end is None
    assert f0.evidence_level == EvidenceLevel.SINGLE_SOURCE

    f1 = findings[1]
    assert f1.title == "Hardcoded JWT Secret"
    assert f1.severity == Severity.MEDIUM
    assert f1.cwe == "CWE-798"
    assert f1.confidence == 0.45  # Default
    assert f1.file_path == "app/core/jwt.py"
    assert f1.line_start == 15


def test_mantis_ingest_malformed_and_partial_input() -> None:
    adapter = MantisAdapter()
    # Malformed inputs
    assert adapter.ingest_findings("") == []
    assert adapter.ingest_findings("not json") == []
    assert adapter.ingest_findings(None) == []
    assert adapter.ingest_findings(12345) == []
    assert adapter.ingest_findings([]) == []

    # Partial inputs
    partial = [
        {"title": ""},  # empty title -> skipped
        {"description": "no title"},  # no title -> skipped
        {"title": "Valid Title Only"},  # minimal valid -> accepted
        "not a dict",  # skipped
    ]
    findings = adapter.ingest_findings(partial)
    assert len(findings) == 1
    assert findings[0].title == "Valid Title Only"
    assert findings[0].severity == Severity.UNKNOWN
    assert findings[0].confidence == 0.45
    assert findings[0].evidence_level == EvidenceLevel.SINGLE_SOURCE
def test_mantis_ingest_false_positive_preserves_status():
    adapter = MantisAdapter()
    sample = {
        "title": "False Positive finding from Mantis",
        "description": "Analysis determined this is a false positive.",
        "status": "FALSE_POSITIVE",
        "severity": "LOW",
        "file_path": "app/utils.py",
        "line_start": 10,
    }
    findings = adapter.ingest_findings(sample)
    assert len(findings) == 1
    f = findings[0]
    assert f.status == FindingStatus.OPEN
    assert f.status != FindingStatus.FALSE_POSITIVE
    assert f.raw_data["mantis_status"] == "FALSE_POSITIVE"


def test_mantis_ingest_duplicate_when_primary_present():
    adapter = MantisAdapter()
    payload = {
        "findings": [
            {
                "id": "mantis-vuln-01",
                "title": "SQL Injection in User Service",
                "description": "User input concatenated directly.",
                "status": "VALID",
                "severity": "HIGH",
                "file_path": "app/users.py",
                "line_start": 20,
            },
            {
                "id": "mantis-vuln-02",
                "title": "SQL Injection in User Service (Duplicate)",
                "description": "Duplicate finding from secondary query.",
                "status": "DUPLICATE",
                "duplicate_of": "mantis-vuln-01",
                "severity": "HIGH",
                "file_path": "app/users.py",
                "line_start": 20,
            },
        ]
    }
    findings = adapter.ingest_findings(payload)
    # Duplicate with primary in batch must NOT create a second actionable finding
    assert len(findings) == 1
    f = findings[0]
    assert f.status == FindingStatus.OPEN
    # Duplicate information attached to primary
    assert len(f.evidences) == 2
    assert "duplicates" in f.raw_data
    assert len(f.raw_data["duplicates"]) == 1
    assert f.raw_data["duplicates"][0]["id"] == "mantis-vuln-02"


def test_mantis_ingest_duplicate_standalone_not_open():
    adapter = MantisAdapter()
    sample = {
        "id": "mantis-dup-standalone",
        "title": "Unlinked Duplicate Issue",
        "description": "Mantis flagged as duplicate without parent in payload.",
        "status": "DUPLICATE",
        "severity": "MEDIUM",
        "file_path": "app/auth.py",
    }
    findings = adapter.ingest_findings(sample)
    assert len(findings) == 1
    f = findings[0]
    # Standalone duplicate stays OPEN; ACCEPTED_BY_DESIGN removed from ingestion
    assert f.status == FindingStatus.OPEN
    assert f.status != FindingStatus.ACCEPTED_BY_DESIGN
    assert f.raw_data["mantis_status"] == "DUPLICATE"
    assert f.raw_data["is_duplicate"] is True


def test_mantis_ingest_malformed_line_numbers_safe():
    adapter = MantisAdapter()
    sample = {
        "title": "Type confusion in lines",
        "file_path": "app/test.py",
        "line_start": {"line": 42},  # dict instead of int
        "line_end": [100],  # list instead of int
    }
    findings = adapter.ingest_findings(sample)
    assert len(findings) == 1
    f = findings[0]
    assert f.line_start is None
    assert f.line_end is None

    # String numeric normalization
    sample_numeric_str = {
        "title": "Numeric string lines",
        "file_path": "app/test.py",
        "line_start": "55",
        "line_end": "60",
    }
    findings2 = adapter.ingest_findings(sample_numeric_str)
    assert len(findings2) == 1
    assert findings2[0].line_start == 55
    assert findings2[0].line_end == 60

    # Non-numeric string lines
    sample_bad_str = {
        "title": "Bad string lines",
        "file_path": "app/test.py",
        "line_start": "line_fifty_five",
        "line_end": "invalid",
    }
    findings3 = adapter.ingest_findings(sample_bad_str)
    assert len(findings3) == 1
    assert findings3[0].line_start is None
    assert findings3[0].line_end is None

    # Boolean lines rejected (bool is subclass of int)
    sample_bool = {
        "title": "Boolean lines",
        "file_path": "app/test.py",
        "line_start": True,
        "line_end": False,
    }
    findings4 = adapter.ingest_findings(sample_bool)
    assert len(findings4) == 1
    assert findings4[0].line_start is None
    assert findings4[0].line_end is None


def test_mantis_repro_status_never_promotes_runtime_validated():
    adapter = MantisAdapter()
    sample = {
        "title": "Claimed verified PoC",
        "repro_status": "reproduced",
        "file_path": "app/core.py",
        "line_start": 1,
    }
    findings = adapter.ingest_findings(sample)
    assert len(findings) == 1
    f = findings[0]
    assert f.evidence_level == EvidenceLevel.SINGLE_SOURCE
    assert f.evidence_level != EvidenceLevel.RUNTIME_VALIDATED


def test_mantis_no_agent_verdict_creates_secops_disposition():
    """No Mantis status alone may produce ACCEPTED_RISK, ACCEPTED_BY_DESIGN,
    FIXED, or FALSE_POSITIVE as a SecOps FindingStatus."""
    adapter = MantisAdapter()
    forbidden = {
        FindingStatus.ACCEPTED_RISK,
        FindingStatus.ACCEPTED_BY_DESIGN,
        FindingStatus.FIXED,
        FindingStatus.FALSE_POSITIVE,
    }
    agent_verdicts = [
        "VALID",
        "PROVISIONALLY_VALID",
        "NEEDS_RESEARCH",
        "FALSE_POSITIVE",
        "FP",
        "DUPLICATE",
    ]
    for verdict in agent_verdicts:
        sample = {
            "title": f"Test finding with verdict {verdict}",
            "description": "Automated disposition guard test.",
            "status": verdict,
            "severity": "MEDIUM",
            "file_path": "app/guard.py",
        }
        findings = adapter.ingest_findings(sample)
    assert len(findings) == 1, f"Expected 1 finding for verdict {verdict}"
    f = findings[0]
    assert f.status not in forbidden, (
        f"Verdict {verdict} must not produce SecOps disposition {f.status}"
    )
    assert f.status == FindingStatus.OPEN
    assert f.raw_data["mantis_status"] == verdict


def test_mantis_ingest_duplicate_before_primary_order_independent() -> None:
    """Duplicate appearing before its primary in the batch attaches to the primary identically."""
    adapter = MantisAdapter()
    payload = {
        "findings": [
            {
                "id": "mantis-vuln-02",
                "title": "SQL Injection in UserService (Duplicate)",
                "description": "Duplicate finding from secondary query.",
                "status": "DUPLICATE",
                "duplicate_of": "mantis-vuln-01",
                "severity": "HIGH",
                "file_path": "app/users.py",
                "line_start": 20,
            },
            {
                "id": "mantis-vuln-01",
                "title": "SQL Injection in User Service",
                "description": "User input concatenated directly.",
                "status": "VALID",
                "severity": "HIGH",
                "file_path": "app/users.py",
                "line_start": 20,
            },
        ]
    }
    findings = adapter.ingest_findings(payload)
    # Order-independent: duplicate attaches to primary, only 1 actionable finding
    assert len(findings) == 1
    f = findings[0]
    assert f.status == FindingStatus.OPEN
    assert f.title == "SQL Injection in User Service"
    assert len(f.evidences) == 2
    assert "duplicates" in f.raw_data
    assert len(f.raw_data["duplicates"]) == 1
    assert f.raw_data["duplicates"][0]["id"] == "mantis-vuln-02"


def test_mantis_ingest_duplicate_when_primary_invalid_fails_safe() -> None:
    """When a primary in the batch is invalid/fails normalization, duplicate remains OPEN."""
    adapter = MantisAdapter()
    # Test duplicate after invalid primary
    payload_after = {
        "findings": [
            {
                "id": "mantis-vuln-invalid",
                # missing title -> fails normalization
                "description": "Malformed finding without title.",
                "status": "VALID",
            },
            {
                "id": "mantis-vuln-dup",
                "title": "Duplicate Finding Safe Fallback",
                "description": "Points to an invalid primary in the same batch.",
                "status": "DUPLICATE",
                "duplicate_of": "mantis-vuln-invalid",
                "severity": "HIGH",
                "file_path": "app/users.py",
                "line_start": 20,
            },
        ]
    }
    findings_after = adapter.ingest_findings(payload_after)
    assert len(findings_after) == 1
    f_after = findings_after[0]
    assert f_after.status == FindingStatus.OPEN
    assert f_after.title == "Duplicate Finding Safe Fallback"
    assert f_after.raw_data["mantis_status"] == "DUPLICATE"
    assert f_after.raw_data["is_duplicate"] is True
    assert f_after.raw_data["duplicate_of"] == "mantis-vuln-invalid"

    # Test duplicate before invalid primary
    payload_before = {
        "findings": [
            {
                "id": "mantis-vuln-dup-2",
                "title": "Duplicate Finding Safe Fallback Reversed",
                "description": "Points to an invalid primary in the same batch (reversed order).",
                "status": "DUPLICATE",
                "duplicate_of": "mantis-vuln-invalid",
                "severity": "HIGH",
                "file_path": "app/users.py",
                "line_start": 20,
            },
            {
                "id": "mantis-vuln-invalid",
                "description": "Malformed finding without title.",
                "status": "VALID",
            },
        ]
    }
    findings_before = adapter.ingest_findings(payload_before)
    assert len(findings_before) == 1
    f_before = findings_before[0]
    assert f_before.status == FindingStatus.OPEN
    assert f_before.title == "Duplicate Finding Safe Fallback Reversed"
    assert f_before.raw_data["mantis_status"] == "DUPLICATE"
    assert f_before.raw_data["is_duplicate"] is True
    assert f_before.raw_data["duplicate_of"] == "mantis-vuln-invalid"


def test_mantis_ingest_duplicate_standalone_with_missing_primary_stays_open() -> None:
    """Standalone duplicate pointing to non-existent primary ID remains OPEN with metadata."""
    adapter = MantisAdapter()
    sample = {
        "id": "mantis-dup-missing-parent",
        "title": "Unlinked Duplicate Issue",
        "description": "Mantis flagged duplicate pointing to non-existent parent.",
        "status": "DUPLICATE",
        "duplicate_of": "never-existed-id",
        "severity": "MEDIUM",
        "file_path": "app/auth.py",
    }
    findings = adapter.ingest_findings(sample)
    assert len(findings) == 1
    f = findings[0]
    assert f.status == FindingStatus.OPEN
    assert f.status != FindingStatus.ACCEPTED_BY_DESIGN
    assert f.raw_data["mantis_status"] == "DUPLICATE"
    assert f.raw_data["is_duplicate"] is True
    assert f.raw_data["duplicate_of"] == "never-existed-id"
