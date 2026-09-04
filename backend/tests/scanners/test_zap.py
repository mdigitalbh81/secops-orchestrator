from pathlib import Path

from app.models.enums import EvidenceLevel, Severity
from app.scanners.zap import ZapScanner
from app.security.runner import RunResult


def test_zap_metadata_and_applicability():
    scanner = ZapScanner()
    assert scanner.name == "zap"

    # Not applicable when target_url is None or empty
    assert scanner.detect_applicability(Path("/workspace"), target_url=None) is False
    assert scanner.detect_applicability(Path("/workspace"), target_url="") is False

    # Applicable when target_url is provided
    assert (
        scanner.detect_applicability(Path("/workspace"), target_url="http://staging-app:3000")
        is True
    )

    cmd = scanner.build_command(Path("/workspace"), target_url="http://staging-app:3000")
    assert "zap-baseline.py" in cmd[0]
    assert "-t" in cmd
    assert "http://staging-app:3000" in cmd


def test_zap_parse_and_normalize(zap_json: str):
    scanner = ZapScanner()
    result = RunResult(return_code=0, stdout=zap_json, stderr="")
    raw = scanner.parse_result(result)
    assert len(raw) == 3

    findings = scanner.normalize_findings(raw)
    assert len(findings) == 3

    # Finding 1: SQL Injection
    f1 = findings[0]
    assert f1.title == "SQL Injection"
    assert f1.severity == Severity.HIGH
    assert f1.cwe == "CWE-89"
    assert f1.url == "http://staging-app:3000/api/users"
    assert f1.evidence_level == EvidenceLevel.RUNTIME_VALIDATED
    assert f1.scanner_name == "zap"
    assert f1.confidence >= 0.70
    assert f1.raw_fingerprint
    assert f1.normalized_fingerprint

    # Finding 2: X-Frame-Options Header Not Set
    f2 = findings[1]
    assert f2.title == "X-Frame-Options Header Not Set"
    assert f2.severity == Severity.MEDIUM
    assert f2.cwe == "CWE-1021"
    assert f2.evidence_level == EvidenceLevel.RUNTIME_VALIDATED

    # Finding 3: Timestamp Disclosure - Unix
    f3 = findings[2]
    assert f3.title == "Timestamp Disclosure - Unix"
    assert f3.severity == Severity.INFO
    assert f3.cwe == "CWE-200"
    assert f3.evidence_level == EvidenceLevel.RUNTIME_VALIDATED


def test_zap_parse_empty_and_corrupt():
    scanner = ZapScanner()
    assert scanner.parse_result(RunResult(return_code=0, stdout="", stderr="")) == []
    assert scanner.parse_result(RunResult(return_code=0, stdout="not valid json", stderr="")) == []
    assert scanner.normalize_findings([]) == []


def test_zap_no_cwe_not_invented():
    scanner = ZapScanner()
    raw = [
        {
            "alert": "Generic Information Leak",
            "riskcode": "1",
            "confidence": "2",
            "desc": "Information disclosure without CWE",
            "cweid": "0",  # ZAP default when unknown
            "url": "http://staging-app:3000/info",
        }
    ]
    findings = scanner.normalize_findings(raw)
    assert len(findings) == 1
    assert findings[0].cwe is None  # Must NOT invent CWE
    assert findings[0].severity == Severity.LOW
