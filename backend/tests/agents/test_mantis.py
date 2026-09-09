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
            mantis_reproduce=True,  # Even if set to true in config, adapter must not activate it
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
