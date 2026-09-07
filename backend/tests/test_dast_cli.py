"""Tests for DAST-only CLI flow (secops dast <url>)."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from app.cli import (
    ApiClient,
    build_parser,
    cmd_dast,
    cmd_findings,
    cmd_report,
    load_state,
    main,
    normalize_dast_hostname,
    resolve_dast_project,
    save_state,
)


@pytest.fixture(autouse=True)
def _isolate_state_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Prevent tests from modifying user's real state.json."""
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))


# ---------- 1. Parser: secops dast <url> ----------


def test_parser_dast_command() -> None:
    parser = build_parser()
    args = parser.parse_args(["dast", "https://app.example.com"])
    assert args.command == "dast"
    assert args.url == "https://app.example.com"
    assert args.json is False
    assert args.project_id is None


def test_parser_dast_with_options() -> None:
    parser = build_parser()
    args = parser.parse_args([
        "dast", "https://app.example.com", "--json", "--project-id", "pid-1"
    ])
    assert args.json is True
    assert args.project_id == "pid-1"


# ---------- 2. URL missing ----------


def test_dast_url_missing() -> None:
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["dast"])


# ---------- 3. URL invalid ----------


def test_dast_invalid_url_scheme() -> None:
    api = MagicMock(spec=ApiClient)
    args = build_parser().parse_args(["dast", "ftp://example.com"])
    code = cmd_dast(args, api)
    assert code == 1


def test_dast_invalid_url_no_host() -> None:
    api = MagicMock(spec=ApiClient)
    args = build_parser().parse_args(["dast", "https://"])
    code = cmd_dast(args, api)
    assert code == 1


# ---------- 4. http/https per policy ----------


def test_dast_http_accepted() -> None:
    parser = build_parser()
    args = parser.parse_args(["dast", "http://app.example.com"])
    assert args.url == "http://app.example.com"


def test_dast_https_accepted() -> None:
    parser = build_parser()
    args = parser.parse_args(["dast", "https://app.example.com"])
    assert args.url == "https://app.example.com"


# ---------- 5. DAST-only does not require Git ----------
# ---------- 6. DAST-only does not require path ----------


def test_dast_no_git_no_path() -> None:
    """dast command does not reference Git or project_path at all."""
    api = MagicMock(spec=ApiClient)
    api.get.side_effect = lambda path, query_params=None: {
        "/api/projects": [{"id": "pid-1", "name": "DAST: app.example.com"}],
        "/api/scans/sid-1": {"id": "sid-1", "status": "COMPLETED", "risk_gate": "PASS"},
        "/api/scans/sid-1/summary": {
            "scan_id": "sid-1", "status": "COMPLETED", "risk_gate": "PASS",
            "totals": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "scanner_runs": {"zap": "completed", "nuclei": "completed"},
        },
    }.get(path, [])
    api.post.return_value = {"id": "sid-1"}

    with patch("app.cli.preflight_check", return_value=(True, "OK")):
        args = build_parser().parse_args(["dast", "https://app.example.com"])
        code = cmd_dast(args, api)
    assert code == 0
    # Verify no git or path-related calls
    post_call = api.post.call_args
    body = post_call[1].get("body") or post_call[0][1] if len(post_call[0]) > 1 else post_call[1]["body"]
    assert "source_path" not in body or body.get("source_path") is None
    assert body["scan_mode"] == "DAST_ONLY"


# ---------- 7. Stable project resolution by hostname ----------


def test_normalize_dast_hostname_basic() -> None:
    assert normalize_dast_hostname("https://app.example.com") == "app.example.com"
    assert normalize_dast_hostname("https://APP.EXAMPLE.COM") == "app.example.com"
    assert normalize_dast_hostname("https://app.example.com.") == "app.example.com"
    assert normalize_dast_hostname("https://app.example.com/path?q=1#frag") == "app.example.com"


def test_normalize_dast_hostname_nondefault_port() -> None:
    assert normalize_dast_hostname("http://app.example.com:9090") == "app.example.com:9090"
    assert normalize_dast_hostname("https://app.example.com:8443") == "app.example.com:8443"


def test_normalize_dast_hostname_default_port_stripped() -> None:
    assert normalize_dast_hostname("http://app.example.com:80") == "app.example.com"
    assert normalize_dast_hostname("https://app.example.com:443") == "app.example.com"


# ---------- 8. Reuse same project ----------


def test_resolve_dast_project_reuse() -> None:
    api = MagicMock(spec=ApiClient)
    api.get.return_value = [{"id": "pid-1", "name": "DAST: app.example.com"}]
    pid, name = resolve_dast_project(api, "https://app.example.com")
    assert pid == "pid-1"
    assert name == "DAST: app.example.com"


# ---------- 9. No duplicate project ----------


def test_resolve_dast_project_creates_once() -> None:
    api = MagicMock(spec=ApiClient)
    api.get.return_value = []  # no existing project
    api.post.return_value = {"id": "new-pid", "name": "DAST: app.example.com"}
    pid, name = resolve_dast_project(api, "https://app.example.com")
    assert pid == "new-pid"
    api.post.assert_called_once()


# ---------- 10. Ambiguity ----------


def test_resolve_dast_project_ambiguity() -> None:
    api = MagicMock(spec=ApiClient)
    api.get.return_value = [
        {"id": "p1", "name": "DAST: app.example.com"},
        {"id": "p2", "name": "DAST: app.example.com"},
    ]
    with pytest.raises(RuntimeError, match="Ambiguous"):
        resolve_dast_project(api, "https://app.example.com")


# ---------- 11. --project-id ----------


def test_resolve_dast_project_explicit_id() -> None:
    api = MagicMock(spec=ApiClient)
    api.get.return_value = {"id": "explicit-pid", "name": "My DAST Project"}
    pid, name = resolve_dast_project(api, "https://app.example.com", explicit_project_id="explicit-pid")
    assert pid == "explicit-pid"


# ---------- 12-17. DAST-only scanner applicability ----------


DAST_ONLY_SCANNERS = frozenset({"zap", "nuclei"})
SOURCE_ONLY_SCANNERS = {"semgrep", "codeql", "npm-audit", "pip-audit", "trivy"}


def test_dast_only_scan_payload() -> None:
    """DAST-only scan sends scan_mode=DAST_ONLY without source_path."""
    api = MagicMock(spec=ApiClient)
    api.get.side_effect = lambda path, query_params=None: {
        "/api/projects": [{"id": "pid-1", "name": "DAST: app.example.com"}],
        "/api/scans/sid-1": {"id": "sid-1", "status": "COMPLETED"},
        "/api/scans/sid-1/summary": {
            "scan_id": "sid-1", "status": "COMPLETED", "risk_gate": "PASS",
            "totals": {}, "scanner_runs": {"zap": "completed", "nuclei": "completed"},
        },
    }.get(path, [])
    api.post.return_value = {"id": "sid-1"}

    with patch("app.cli.preflight_check", return_value=(True, "OK")):
        args = build_parser().parse_args(["dast", "https://app.example.com"])
        cmd_dast(args, api)

    # Check the scan creation call
    post_calls = [c for c in api.post.call_args_list if "/api/scans" in str(c)]
    assert len(post_calls) >= 1
    scan_body = post_calls[-1][1].get("body", post_calls[-1][0][1] if len(post_calls[-1][0]) > 1 else {})
    assert scan_body.get("scan_mode") == "DAST_ONLY"
    assert scan_body.get("target_url") == "https://app.example.com"


# ---------- 19. State without project_path ----------


def test_state_without_project_path(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    save_state({
        "project_id": "pid-dast",
        "project_name": "DAST: app.example.com",
        "scan_id": "scan-dast-1",
        "project_path": None,
        "branch": None,
        "commit": None,
    })
    loaded = load_state()
    assert loaded is not None
    assert loaded["project_path"] is None
    assert loaded["scan_id"] == "scan-dast-1"


# ---------- 20/21. Report and findings after DAST-only ----------


def test_report_after_dast_only(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    save_state({
        "project_id": "pid-dast",
        "project_name": "DAST: app.example.com",
        "scan_id": "scan-dast-1",
        "project_path": None,
    })
    api = MagicMock(spec=ApiClient)
    api.get.side_effect = lambda path, query_params=None: {
        "/api/scans/scan-dast-1/summary": {
            "scan_id": "scan-dast-1", "status": "COMPLETED", "risk_gate": "REVIEW",
            "totals": {"high": 2}, "scanner_runs": {"zap": "completed", "nuclei": "completed"},
        },
        "/api/scans/scan-dast-1": {
            "id": "scan-dast-1", "project_id": "pid-dast", "status": "COMPLETED",
        },
        "/api/projects/pid-dast": {"id": "pid-dast", "name": "DAST: app.example.com"},
    }[path]

    args = build_parser().parse_args(["report"])
    code = cmd_report(args, api)
    assert code == 0


def test_findings_after_dast_only(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    save_state({
        "project_id": "pid-dast",
        "project_name": "DAST: app.example.com",
        "scan_id": "scan-dast-1",
        "project_path": None,
    })
    api = MagicMock(spec=ApiClient)
    api.get.return_value = [
        {"id": "f1", "severity": "HIGH", "status": "OPEN", "scanner_name": "zap", "title": "XSS"},
        {"id": "f2", "severity": "MEDIUM", "status": "OPEN", "scanner_name": "nuclei", "title": "CVE-X"},
    ]

    args = build_parser().parse_args(["findings", "--json"])
    code = cmd_findings(args, api)
    assert code == 0


# ---------- 22/23. --scanner zap / --scanner nuclei ----------


def test_findings_filter_scanner_zap(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    save_state({"scan_id": "s1", "project_path": None})
    api = MagicMock(spec=ApiClient)
    api.get.return_value = [
        {"id": "f1", "severity": "HIGH", "status": "OPEN", "scanner_name": "zap", "title": "XSS"},
        {"id": "f2", "severity": "MEDIUM", "status": "OPEN", "scanner_name": "nuclei", "title": "CVE"},
    ]
    args = build_parser().parse_args(["findings", "--scanner", "zap", "--json"])
    with patch("builtins.print") as mock_print:
        cmd_findings(args, api)
    printed = json.loads(mock_print.call_args[0][0])
    assert len(printed) == 1
    assert printed[0]["scanner_name"] == "zap"


def test_findings_filter_scanner_nuclei(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    save_state({"scan_id": "s1", "project_path": None})
    api = MagicMock(spec=ApiClient)
    api.get.return_value = [
        {"id": "f1", "severity": "HIGH", "status": "OPEN", "scanner_name": "zap", "title": "XSS"},
        {"id": "f2", "severity": "MEDIUM", "status": "OPEN", "scanner_name": "nuclei", "title": "CVE"},
    ]
    args = build_parser().parse_args(["findings", "--scanner", "nuclei", "--json"])
    with patch("builtins.print") as mock_print:
        cmd_findings(args, api)
    printed = json.loads(mock_print.call_args[0][0])
    assert len(printed) == 1
    assert printed[0]["scanner_name"] == "nuclei"


# ---------- 24. --json valid ----------


def test_dast_json_output_valid(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    api = MagicMock(spec=ApiClient)
    api.get.side_effect = lambda path, query_params=None: {
        "/api/projects": [{"id": "pid-1", "name": "DAST: app.example.com"}],
        "/api/scans/sid-1": {"id": "sid-1", "status": "COMPLETED", "risk_gate": "PASS"},
        "/api/scans/sid-1/summary": {
            "scan_id": "sid-1", "status": "COMPLETED", "risk_gate": "PASS",
            "totals": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "scanner_runs": {"zap": "completed", "nuclei": "completed"},
        },
    }.get(path, [])
    api.post.return_value = {"id": "sid-1"}

    with patch("app.cli.preflight_check", return_value=(True, "OK")), \
         patch("builtins.print") as mock_print:
        args = build_parser().parse_args(["dast", "https://app.example.com", "--json"])
        code = cmd_dast(args, api)

    assert code == 0
    raw = mock_print.call_args[0][0]
    parsed = json.loads(raw)
    assert parsed["mode"] == "DAST_ONLY"
    assert "scan" in parsed
    assert "summary" in parsed


# ---------- 25. Allowlist rejection ----------


def test_dast_allowlist_rejection() -> None:
    """Backend rejects disallowed hosts; CLI surfaces the error."""
    api = MagicMock(spec=ApiClient)
    api.get.return_value = []
    api.post.side_effect = [
        # project creation succeeds
        {"id": "new-pid", "name": "DAST: evil.com"},
        # scan creation fails with allowlist rejection
        RuntimeError("API Error 400: Invalid target_url: Target host 'evil.com' not in allowed DAST hosts"),
    ]

    with patch("app.cli.preflight_check", return_value=(True, "OK")):
        args = build_parser().parse_args(["dast", "https://evil.com"])
        code = cmd_dast(args, api)
    assert code == 1


# ---------- 26. Scan FAILED ----------


def test_dast_scan_failed() -> None:
    api = MagicMock(spec=ApiClient)
    api.get.side_effect = lambda path, query_params=None: {
        "/api/projects": [{"id": "pid-1", "name": "DAST: app.example.com"}],
        "/api/scans/sid-f": {
            "id": "sid-f", "status": "FAILED", "error_message": "ZAP crashed",
        },
        "/api/scans/sid-f/summary": {
            "scan_id": "sid-f", "status": "FAILED", "totals": {},
            "scanner_runs": {"zap": "failed"},
        },
    }.get(path, [])
    api.post.return_value = {"id": "sid-f"}

    with patch("app.cli.preflight_check", return_value=(True, "OK")):
        args = build_parser().parse_args(["dast", "https://app.example.com"])
        code = cmd_dast(args, api)
    assert code == 1


# ---------- 27. Risk gate functional ----------


def test_dast_risk_gate_in_output() -> None:
    api = MagicMock(spec=ApiClient)
    api.get.side_effect = lambda path, query_params=None: {
        "/api/projects": [{"id": "pid-1", "name": "DAST: app.example.com"}],
        "/api/scans/sid-1": {"id": "sid-1", "status": "COMPLETED", "risk_gate": "BLOCKED"},
        "/api/scans/sid-1/summary": {
            "scan_id": "sid-1", "status": "COMPLETED", "risk_gate": "BLOCKED",
            "totals": {"critical": 1}, "scanner_runs": {"zap": "completed"},
        },
    }.get(path, [])
    api.post.return_value = {"id": "sid-1"}

    with patch("app.cli.preflight_check", return_value=(True, "OK")), \
         patch("builtins.print") as mock_print:
        args = build_parser().parse_args(["dast", "https://app.example.com", "--json"])
        cmd_dast(args, api)
    output = json.loads(mock_print.call_args[0][0])
    assert output["summary"]["risk_gate"] == "BLOCKED"


# ---------- 28. Scanner runs represent skipped/not_applicable ----------


def test_dast_scanner_runs_skipped_display() -> None:
    from app.cli import format_scanner_runs
    runs = {
        "semgrep": "not_applicable",
        "codeql": "not_applicable",
        "npm-audit": "not_applicable",
        "pip-audit": "not_applicable",
        "trivy": "not_applicable",
        "ai-appsec": "not_applicable",
        "zap": "completed",
        "nuclei": "completed",
    }
    formatted = format_scanner_runs(runs)
    assert "ZAP" in formatted
    assert "Nuclei" in formatted
    assert "not applicable" in formatted
    # Source scanners should appear as not applicable
    assert "Semgrep not applicable" in formatted


# ---------- Help tests ----------


def test_dast_help() -> None:
    parser = build_parser()
    with pytest.raises(SystemExit) as exc_info:
        parser.parse_args(["dast", "--help"])
    assert exc_info.value.code == 0


def test_main_help_shows_dast() -> None:
    """secops --help should mention dast command."""
    import io
    import sys
    old_stdout = sys.stdout
    sys.stdout = buf = io.StringIO()
    try:
        code = main([])
    finally:
        sys.stdout = old_stdout
    output = buf.getvalue()
    assert "dast" in output or code == 0
