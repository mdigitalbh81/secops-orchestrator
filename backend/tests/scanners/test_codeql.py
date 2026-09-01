from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from app.models.enums import Severity
from app.scanners.codeql import (
    CodeQLScanner,
    extract_cwe_from_tags,
    map_sarif_severity,
)
from app.security.runner import RunResult

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"


def test_map_sarif_severity_security_severity():
    assert map_sarif_severity(None, security_severity=9.5) == Severity.CRITICAL
    assert map_sarif_severity(None, security_severity=8.0) == Severity.HIGH
    assert map_sarif_severity(None, security_severity=5.5) == Severity.MEDIUM
    assert map_sarif_severity(None, security_severity=2.0) == Severity.LOW


def test_map_sarif_severity_level_and_problem():
    assert map_sarif_severity("error") == Severity.HIGH
    assert map_sarif_severity("warning") == Severity.MEDIUM
    assert map_sarif_severity("note") == Severity.LOW
    assert map_sarif_severity("none") == Severity.LOW
    assert map_sarif_severity(None, problem_severity="critical") == Severity.CRITICAL
    assert map_sarif_severity("invalid") == Severity.UNKNOWN


def test_extract_cwe_from_tags():
    tags = ["security", "external/cwe/cwe-89", "external/cwe/cwe-089"]
    assert extract_cwe_from_tags(tags) == "CWE-89"

    tags2 = ["cwe-78", "maintainability"]
    assert extract_cwe_from_tags(tags2) == "CWE-78"

    assert extract_cwe_from_tags(["security", "database"]) is None


def test_codeql_detect_languages_python(tmp_path: Path):
    (tmp_path / "main.py").write_text("print('hello')", encoding="utf-8")
    scanner = CodeQLScanner()
    langs = scanner.detect_languages(tmp_path)
    assert langs == ["python"]
    assert scanner.detect_applicability(tmp_path) is True


def test_codeql_detect_languages_javascript(tmp_path: Path):
    (tmp_path / "index.ts").write_text("const a = 1;", encoding="utf-8")
    scanner = CodeQLScanner()
    langs = scanner.detect_languages(tmp_path)
    assert langs == ["javascript"]
    assert scanner.detect_applicability(tmp_path) is True


def test_codeql_detect_languages_multi(tmp_path: Path):
    (tmp_path / "app.py").write_text("print(1)", encoding="utf-8")
    (tmp_path / "app.js").write_text("console.log(1)", encoding="utf-8")
    scanner = CodeQLScanner()
    langs = scanner.detect_languages(tmp_path)
    assert langs == ["javascript", "python"]
    assert scanner.detect_applicability(tmp_path) is True


def test_codeql_detect_languages_empty(tmp_path: Path):
    (tmp_path / "README.md").write_text("# Doc", encoding="utf-8")
    scanner = CodeQLScanner()
    assert scanner.detect_languages(tmp_path) == []
    assert scanner.detect_applicability(tmp_path) is False


@pytest.mark.asyncio
async def test_codeql_is_available_true():
    scanner = CodeQLScanner()
    with patch("app.scanners.codeql.run_command", new_callable=AsyncMock) as mock_run:
        mock_run.return_value = RunResult(return_code=0, stdout='{"version": "2.19.0"}', stderr="")
        assert await scanner.is_available() is True


@pytest.mark.asyncio
async def test_codeql_is_available_false():
    scanner = CodeQLScanner()
    with patch("app.scanners.codeql.run_command", new_callable=AsyncMock) as mock_run:
        mock_run.return_value = RunResult(return_code=-1, stdout="", stderr="Command not found")
        assert await scanner.is_available() is False


def test_codeql_parse_and_normalize_sarif():
    sarif_content = (FIXTURES_DIR / "codeql_output.sarif").read_text(encoding="utf-8")
    scanner = CodeQLScanner()
    result = RunResult(return_code=0, stdout=sarif_content, stderr="")

    raw_findings = scanner.parse_result(result)
    assert len(raw_findings) == 2

    normalized = scanner.normalize_findings(raw_findings)
    assert len(normalized) == 2

    sql_finding = normalized[0]
    assert sql_finding.title == "SQL query built from user-controlled sources"
    assert sql_finding.severity == Severity.HIGH
    assert sql_finding.cwe == "CWE-89"
    assert sql_finding.file_path == "app/db/user_repo.py"
    assert sql_finding.line_start == 25
    assert sql_finding.confidence == 0.70
    assert sql_finding.scanner_name == "codeql"

    cmd_finding = normalized[1]
    assert cmd_finding.title == "Uncontrolled command line"
    assert cmd_finding.severity == Severity.CRITICAL
    assert cmd_finding.cwe == "CWE-78"
    assert cmd_finding.file_path == "app/utils/exec.py"
    assert cmd_finding.line_start == 42
    assert cmd_finding.confidence == 0.70


@pytest.mark.asyncio
async def test_codeql_execute_workflow(tmp_path: Path):
    (tmp_path / "test.py").write_text("print('test')", encoding="utf-8")
    scanner = CodeQLScanner()

    sarif_fixture = (FIXTURES_DIR / "codeql_output.sarif").read_text(encoding="utf-8")

    async def mock_run_cmd(argv, cwd=None, config=None):
        if "create" in argv:
            return RunResult(return_code=0, stdout="Database created", stderr="")
        if "analyze" in argv:
            for arg in argv:
                if arg.startswith("--output="):
                    sarif_path = Path(arg.split("=", 1)[1])
                    sarif_path.write_text(sarif_fixture, encoding="utf-8")
            return RunResult(return_code=0, stdout="Analysis completed", stderr="")
        return RunResult(return_code=0, stdout="", stderr="")

    with patch("app.scanners.codeql.run_command", side_effect=mock_run_cmd):
        res = await scanner.execute(tmp_path)
        assert res.return_code == 0
        parsed = json.loads(res.stdout)
        assert len(parsed.get("runs", [])) > 0
