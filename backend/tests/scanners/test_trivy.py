from pathlib import Path

import pytest

from app.models.enums import Severity
from app.scanners.trivy import TrivyScanner
from app.security.runner import RunResult


def test_trivy_applicability(tmp_path: Path):
    scanner = TrivyScanner()
    # Trivy fs scan applies to any valid project directory
    assert scanner.detect_applicability(tmp_path)
    (tmp_path / "Dockerfile").write_text("FROM alpine")
    assert scanner.detect_applicability(tmp_path)


def test_trivy_build_command(tmp_path: Path):
    scanner = TrivyScanner()
    cmd = scanner.build_command(tmp_path)
    assert cmd == [
        "trivy",
        "fs",
        "--format",
        "json",
        "--no-progress",
        "--scanners",
        "vuln",
        str(tmp_path),
    ]


def test_trivy_parse_result_error_raises():
    scanner = TrivyScanner()
    result = RunResult(return_code=1, stdout="", stderr="DB error: failed to download DB")
    with pytest.raises(RuntimeError, match="Trivy execution failed"):
        scanner.parse_result(result)


def test_trivy_parse_result_invalid_json_raises():
    scanner = TrivyScanner()
    result = RunResult(return_code=0, stdout="not valid json", stderr="some error")
    with pytest.raises(RuntimeError, match="Failed to parse trivy JSON output"):
        scanner.parse_result(result)


def test_trivy_parse_and_normalize(trivy_json: str):
    scanner = TrivyScanner()
    result = RunResult(return_code=0, stdout=trivy_json, stderr="")
    raw = scanner.parse_result(result)
    assert len(raw) == 3

    findings = scanner.normalize_findings(raw)
    assert len(findings) == 3

    # Critical finding in base image
    critical = next(f for f in findings if f.severity == Severity.CRITICAL)
    assert critical.cve == "CVE-2023-12345"
    assert critical.package_name == "base-image-lib"
    assert critical.fixed_version == "0.2.0"
    assert critical.confidence == 0.7
    assert critical.cwe == "CWE-94"

    # Lodash finding
    lodash = next(f for f in findings if f.package_name == "lodash")
    assert lodash.cve == "CVE-2019-10744"
    assert lodash.severity == Severity.HIGH
    assert lodash.cwe == "CWE-1321"
