from pathlib import Path

from app.models.enums import Severity
from app.scanners.npm_audit import NpmAuditScanner
from app.security.runner import RunResult


def test_npm_audit_applicability(tmp_path: Path):
    scanner = NpmAuditScanner()
    assert not scanner.detect_applicability(tmp_path)
    (tmp_path / "package.json").write_text("{}")
    assert scanner.detect_applicability(tmp_path)


def test_npm_audit_command(tmp_path: Path):
    scanner = NpmAuditScanner()
    assert scanner.build_command(tmp_path) == ["npm", "audit", "--json"]


def test_npm_audit_parse_and_normalize(npm_audit_json: str):
    scanner = NpmAuditScanner()
    result = RunResult(return_code=1, stdout=npm_audit_json, stderr="")
    raw = scanner.parse_result(result)
    assert len(raw) == 2

    findings = scanner.normalize_findings(raw)
    assert len(findings) == 2

    # lodash
    lodash = next(f for f in findings if f.package_name == "lodash")
    assert lodash.severity == Severity.HIGH
    assert lodash.cve == "CVE-2019-10744"
    assert lodash.fixed_version == "4.17.21"
    assert lodash.confidence == 0.7
    assert lodash.scanner_name == "npm-audit"

    # axios
    axios = next(f for f in findings if f.package_name == "axios")
    assert axios.severity == Severity.CRITICAL
    assert axios.cve == "CVE-2020-28168"
    assert axios.fixed_version == "0.21.1"
    assert axios.confidence == 0.7
