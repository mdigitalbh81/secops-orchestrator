from pathlib import Path

from app.scanners.pip_audit import PipAuditScanner
from app.security.runner import RunResult


def test_pip_audit_applicability(tmp_path: Path):
    scanner = PipAuditScanner()
    assert not scanner.detect_applicability(tmp_path)

    (tmp_path / "requirements.txt").write_text("requests==2.20.0")
    assert scanner.detect_applicability(tmp_path)

    tmp_path2 = tmp_path / "pyproj"
    tmp_path2.mkdir()
    (tmp_path2 / "pyproject.toml").write_text("[project]")
    assert scanner.detect_applicability(tmp_path2)


def test_pip_audit_build_command(tmp_path: Path):
    scanner = PipAuditScanner()
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("flask")
    cmd = scanner.build_command(tmp_path)
    assert cmd == ["pip-audit", "--format", "json", "--requirement", str(req_file)]


def test_pip_audit_parse_and_normalize(pip_audit_json: str):
    scanner = PipAuditScanner()
    result = RunResult(return_code=1, stdout=pip_audit_json, stderr="")
    raw = scanner.parse_result(result)
    assert len(raw) == 3

    findings = scanner.normalize_findings(raw)
    assert len(findings) == 2  # safe-lib has no vulns

    urllib = next(f for f in findings if f.package_name == "urllib3")
    assert urllib.cve == "CVE-2021-33503"
    assert urllib.fixed_version == "1.26.5"
    assert urllib.installed_version == "1.26.4"
    assert urllib.confidence == 0.7

    jinja = next(f for f in findings if f.package_name == "jinja2")
    assert jinja.cve == "CVE-2020-28493"
    assert jinja.fixed_version == "2.11.3"
