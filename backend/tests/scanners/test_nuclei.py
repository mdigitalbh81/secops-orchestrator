from pathlib import Path

from app.models.enums import EvidenceLevel, Severity
from app.scanners.nuclei import NucleiScanner
from app.security.runner import RunResult


def test_nuclei_metadata_and_applicability():
    scanner = NucleiScanner()
    assert scanner.name == "nuclei"

    # Not applicable when target_url is None or empty
    assert scanner.detect_applicability(Path("/workspace"), target_url=None) is False
    assert scanner.detect_applicability(Path("/workspace"), target_url="") is False

    # Applicable when target_url is provided
    assert (
        scanner.detect_applicability(Path("/workspace"), target_url="http://staging-app:3000")
        is True
    )

    cmd = scanner.build_command(Path("/workspace"), target_url="http://staging-app:3000")
    assert "nuclei" in cmd[0]
    assert "-u" in cmd
    assert "http://staging-app:3000" in cmd
    assert "-jsonl" in cmd


def test_nuclei_parse_and_normalize(nuclei_jsonl: str):
    scanner = NucleiScanner()
    result = RunResult(return_code=0, stdout=nuclei_jsonl, stderr="")
    raw = scanner.parse_result(result)
    assert len(raw) == 3

    findings = scanner.normalize_findings(raw)
    assert len(findings) == 3

    # Finding 1: Apache RCE (CVE-2021-41773)
    f1 = findings[0]
    assert "Apache" in f1.title
    assert f1.severity == Severity.CRITICAL
    assert f1.cve == "CVE-2021-41773"
    assert f1.cwe == "CWE-22"
    assert f1.url == "http://staging-app:3000/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"
    assert f1.evidence_level == EvidenceLevel.RUNTIME_VALIDATED
    assert f1.scanner_name == "nuclei"
    assert f1.confidence >= 0.80
    assert f1.raw_fingerprint
    assert f1.normalized_fingerprint

    # Finding 2: CORS Misconfiguration
    f2 = findings[1]
    assert "CORS" in f2.title
    assert f2.severity == Severity.MEDIUM
    assert f2.cwe == "CWE-942"
    assert f2.evidence_level == EvidenceLevel.RUNTIME_VALIDATED

    # Finding 3: Tech Detect (Info)
    f3 = findings[2]
    assert "FastAPI" in f3.title
    assert f3.severity == Severity.INFO
    assert f3.evidence_level == EvidenceLevel.RUNTIME_VALIDATED


def test_nuclei_parse_empty_and_corrupt():
    scanner = NucleiScanner()
    assert scanner.parse_result(RunResult(return_code=0, stdout="", stderr="")) == []
    assert scanner.parse_result(RunResult(return_code=0, stdout="not valid json", stderr="")) == []
    assert scanner.normalize_findings([]) == []
