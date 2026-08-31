from pathlib import Path

from app.models.enums import Severity
from app.scanners.semgrep import SemgrepScanner
from app.security.runner import RunResult


def test_semgrep_adapter_metadata():
    scanner = SemgrepScanner()
    assert scanner.name == "semgrep"
    assert scanner.detect_applicability(Path("/any/path")) is True
    cmd = scanner.build_command(Path("/project"))
    assert cmd == ["semgrep", "scan", "--json", "--config", "auto", "/project"]


def test_semgrep_parse_and_normalize(semgrep_json: str):
    scanner = SemgrepScanner()
    result = RunResult(return_code=0, stdout=semgrep_json, stderr="")
    raw = scanner.parse_result(result)
    assert len(raw) == 3

    findings = scanner.normalize_findings(raw)
    assert len(findings) == 3

    f1 = findings[0]
    assert f1.title == "python.lang.security.deserialization.pickle.avoid-pickle"
    assert f1.severity == Severity.HIGH
    assert f1.cwe == "CWE-502"
    assert f1.file_path == "app/utils.py"
    assert f1.line_start == 42
    assert f1.line_end == 42
    assert f1.scanner_name == "semgrep"
    assert f1.raw_fingerprint != ""
    assert f1.normalized_fingerprint != ""

    f2 = findings[1]
    assert f2.severity == Severity.MEDIUM
    assert f2.cwe == "CWE-798"
    assert f2.file_path == "app/config.py"

    f3 = findings[2]
    assert f3.severity == Severity.INFO


def test_semgrep_parse_empty():
    scanner = SemgrepScanner()
    result = RunResult(return_code=0, stdout="", stderr="")
    assert scanner.parse_result(result) == []
    assert scanner.normalize_findings([]) == []
