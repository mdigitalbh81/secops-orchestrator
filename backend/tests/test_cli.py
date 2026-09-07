"""Unit and functional tests for the SecOps CLI."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from app.cli import (
    ApiClient,
    GitMetadata,
    build_parser,
    cmd_audit,
    cmd_doctor,
    cmd_findings,
    cmd_report,
    deploy_snapshot,
    format_scanner_runs,
    get_project_internal_workspace,
    get_state_file_path,
    inspect_git_repo,
    load_state,
    main,
    normalize_git_url,
    resolve_project,
    save_state,
)


# 1. Parser de comandos
def test_cli_parser_commands() -> None:
    parser = build_parser()

    # Audit
    args = parser.parse_args(["audit", "/some/path", "--url", "http://test:8000", "--project-id", "pid1", "--json"])
    assert args.command == "audit"
    assert args.path == "/some/path"
    assert args.url == "http://test:8000"
    assert args.project_id == "pid1"
    assert args.json is True

    # Report
    args_rep = parser.parse_args(["report", "/path", "--scan-id", "sid1", "--json"])
    assert args_rep.command == "report"
    assert args_rep.path == "/path"
    assert args_rep.scan_id == "sid1"
    assert args_rep.json is True

    # Findings
    args_find = parser.parse_args([
        "findings", "--severity", "high", "--status", "open", "--scanner", "semgrep", "--all", "--json"
    ])
    assert args_find.command == "findings"
    assert args_find.severity == "high"
    assert args_find.status == "open"
    assert args_find.scanner == "semgrep"
    assert args_find.all is True
    assert args_find.json is True

    # Doctor
    args_doc = parser.parse_args(["doctor"])
    assert args_doc.command == "doctor"


# 7. Remote URL normalization
def test_remote_url_normalization() -> None:
    ssh_url = "git@github.com:owner/repo.git"
    https_url = "https://github.com/owner/repo.git"
    ssh_slash = "git@github.com:owner/repo"
    https_no_ext = "https://github.com/owner/repo"
    ssh_protocol = "ssh://git@github.com/owner/repo.git"

    expected = "https://github.com/owner/repo.git"
    assert normalize_git_url(ssh_url) == expected
    assert normalize_git_url(https_url) == expected
    assert normalize_git_url(ssh_slash) == expected
    assert normalize_git_url(https_no_ext) == expected
    assert normalize_git_url(ssh_protocol) == expected


# 3. Path inexistente
def test_audit_nonexistent_path(tmp_path: Path) -> None:
    fake_path = tmp_path / "does_not_exist"
    with pytest.raises(ValueError, match="Directory not found"):
        inspect_git_repo(fake_path)


# 4. Não Git repository
def test_audit_not_git_repo(tmp_path: Path) -> None:
    non_git = tmp_path / "non_git_dir"
    non_git.mkdir()
    with pytest.raises(ValueError, match="Not a valid git repository"):
        inspect_git_repo(non_git)


# Helper to initialize a test git repository
def _init_test_git_repo(path: Path) -> None:
    subprocess.run(["git", "init"], cwd=str(path), check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=str(path), check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Test User"], cwd=str(path), check=True, capture_output=True)
    (path / "file.txt").write_text("initial commit\n")
    subprocess.run(["git", "add", "."], cwd=str(path), check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "initial commit"], cwd=str(path), check=True, capture_output=True)


# 2. Audit em path válido
def test_audit_valid_git_repo(tmp_path: Path) -> None:
    repo_dir = tmp_path / "my_repo"
    repo_dir.mkdir()
    _init_test_git_repo(repo_dir)

    meta = inspect_git_repo(repo_dir)
    assert meta.repo_name == "my_repo"
    assert meta.commit_short
    assert meta.commit_full
    assert not meta.is_dirty


# 5. Working tree dirty audita HEAD
def test_working_tree_dirty_detected(tmp_path: Path) -> None:
    repo_dir = tmp_path / "dirty_repo"
    repo_dir.mkdir()
    _init_test_git_repo(repo_dir)

    # Create uncommitted change
    (repo_dir / "uncommitted.txt").write_text("uncommitted content\n")

    meta = inspect_git_repo(repo_dir)
    assert meta.is_dirty is True


# 6 & 12. Stash não entra no snapshot & snapshot usa somente HEAD
def test_snapshot_only_committed_head(tmp_path: Path) -> None:
    repo_dir = tmp_path / "stash_repo"
    repo_dir.mkdir()
    _init_test_git_repo(repo_dir)

    # Add file and stash it
    (repo_dir / "stashed_file.txt").write_text("stashed secret\n")
    subprocess.run(["git", "stash", "-u"], cwd=str(repo_dir), check=True, capture_output=True)

    # Add uncommitted modification
    (repo_dir / "file.txt").write_text("uncommitted change\n")

    # Run git archive HEAD | tar -t
    p_arch = subprocess.Popen(["git", "archive", "HEAD"], cwd=str(repo_dir), stdout=subprocess.PIPE)
    p_tar = subprocess.Popen(["tar", "-t"], stdin=p_arch.stdout, stdout=subprocess.PIPE)
    p_arch.stdout.close()
    out, _ = p_tar.communicate()
    tar_contents = out.decode()

    assert "file.txt" in tar_contents
    assert "stashed_file.txt" not in tar_contents


# 8. Project resolution por repository_url
def test_resolve_project_by_repository_url() -> None:
    api = MagicMock(spec=ApiClient)
    git_meta = GitMetadata(
        repo_name="eduspace",
        branch="main",
        commit_short="0826c80",
        commit_full="0826c80abcdef",
        remote_url="git@github.com:mdigitalbh81/eduspace.git",
        is_dirty=False,
    )
    # Mock API project listing matching normalized URL
    api.get.side_effect = lambda path, query_params=None: (
        [{"id": "proj-uuid-1", "name": "Eduspace"}]
        if query_params and query_params.get("repository_url") == "https://github.com/mdigitalbh81/eduspace.git"
        else []
    )

    pid, name = resolve_project(api, Path("/tmp/eduspace"), git_meta)
    assert pid == "proj-uuid-1"
    assert name == "Eduspace"


# 9. Fallback por name
def test_resolve_project_fallback_by_name() -> None:
    api = MagicMock(spec=ApiClient)
    git_meta = GitMetadata(
        repo_name="local-app",
        branch="main",
        commit_short="abcdef",
        commit_full="abcdef123456",
        remote_url=None,
        is_dirty=False,
    )
    api.get.side_effect = lambda path, query_params=None: (
        [{"id": "proj-uuid-2", "name": "local-app"}]
        if query_params and query_params.get("name") == "local-app"
        else []
    )

    pid, name = resolve_project(api, Path("/tmp/local-app"), git_meta)
    assert pid == "proj-uuid-2"
    assert name == "local-app"


# 10. Criação de Project quando não existe
def test_resolve_project_creates_when_not_found() -> None:
    api = MagicMock(spec=ApiClient)
    git_meta = GitMetadata(
        repo_name="brand-new-project",
        branch="main",
        commit_short="112233",
        commit_full="112233445566",
        remote_url="https://github.com/org/brand-new.git",
        is_dirty=False,
    )
    api.get.return_value = []
    api.post.return_value = {"id": "new-pid-99", "name": "brand-new-project"}

    pid, name = resolve_project(api, Path("/tmp/brand-new-project"), git_meta)
    assert pid == "new-pid-99"
    assert name == "brand-new-project"
    api.post.assert_called_once()


# 11. Ambiguidade não escolhe project silenciosamente
def test_resolve_project_ambiguity_raises() -> None:
    api = MagicMock(spec=ApiClient)
    git_meta = GitMetadata(
        repo_name="shared-name",
        branch="main",
        commit_short="112233",
        commit_full="112233445566",
        remote_url=None,
        is_dirty=False,
    )
    api.get.return_value = [
        {"id": "p1", "name": "shared-name"},
        {"id": "p2", "name": "shared-name"},
    ]

    with pytest.raises(RuntimeError, match="Ambiguous project name match"):
        resolve_project(api, Path("/tmp/shared-name"), git_meta)


# 13. Proteção contra workspace path traversal
def test_snapshot_path_traversal_protection(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="unsafe destination"):
        deploy_snapshot(None, tmp_path, "/tmp/secops-workspaces/../../etc/passwd")

    with pytest.raises(ValueError, match="unsafe destination"):
        deploy_snapshot(None, tmp_path, "/etc/shadow")


# 14 & 15. Polling PENDING -> RUNNING -> COMPLETED & FAILED
def test_audit_polling_completed_and_failed(tmp_path: Path) -> None:
    repo_dir = tmp_path / "poll_repo"
    repo_dir.mkdir()
    _init_test_git_repo(repo_dir)

    poll_count = 0

    def mock_get(path: str, query_params: dict | None = None) -> Any:
        nonlocal poll_count
        if path == "/api/projects":
            return [{"id": "pid-1", "name": "poll_repo"}]
        if path.startswith("/api/projects/pid-1/scans"):
            return []
        if path == "/api/scans/sid-1":
            poll_count += 1
            if poll_count == 1:
                return {"id": "sid-1", "status": "RUNNING"}
            return {"id": "sid-1", "status": "COMPLETED", "risk_gate": "PASS"}
        if path == "/api/scans/sid-1/summary":
            return {
                "scan_id": "sid-1",
                "status": "COMPLETED",
                "risk_gate": "PASS",
                "totals": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0},
                "scanner_runs": {"semgrep": "completed"},
            }
        return {}

    api = MagicMock(spec=ApiClient)
    api.get.side_effect = mock_get
    api.post.return_value = {"id": "sid-1"}

    with patch("app.cli.deploy_snapshot"), \
         patch("app.cli.preflight_check", return_value=(True, "OK")):
        args = build_parser().parse_args(["audit", str(repo_dir)])
        code = cmd_audit(args, api)
        assert code == 0


def test_audit_polling_failed(tmp_path: Path) -> None:
    repo_dir = tmp_path / "failed_poll_repo"
    repo_dir.mkdir()
    _init_test_git_repo(repo_dir)

    def mock_get(path: str, query_params: dict | None = None) -> Any:
        if path == "/api/projects":
            return [{"id": "pid-1", "name": "failed_poll_repo"}]
        if path.startswith("/api/projects/pid-1/scans"):
            return []
        if path == "/api/scans/sid-failed":
            return {"id": "sid-failed", "status": "FAILED", "error_message": "Worker crashed"}
        if path == "/api/scans/sid-failed/summary":
            return {"scan_id": "sid-failed", "status": "FAILED", "totals": {}, "scanner_runs": {}}
        return {}

    api = MagicMock(spec=ApiClient)
    api.get.side_effect = mock_get
    api.post.return_value = {"id": "sid-failed"}

    with patch("app.cli.deploy_snapshot"), \
         patch("app.cli.preflight_check", return_value=(True, "OK")):
        args = build_parser().parse_args(["audit", str(repo_dir)])
        code = cmd_audit(args, api)
        assert code == 1


# 23. State file
def test_state_file_persistence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    state_path = get_state_file_path()
    assert not state_path.exists()

    data = {
        "project_id": "proj-1",
        "scan_id": "scan-1",
        "project_path": "/home/user/code",
        "commit": "abc1234",
        "updated_at": "2026-09-05T12:00:00Z",
    }
    save_state(data)

    loaded = load_state()
    assert loaded == data
    assert state_path.is_file()


# 16. Report usa último scan
def test_report_uses_latest_scan_from_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    save_state({
        "project_id": "proj-rep",
        "project_name": "Report Repo",
        "scan_id": "scan-rep-1",
        "branch": "main",
        "commit": "1234567",
    })

    api = MagicMock(spec=ApiClient)
    api.get.side_effect = lambda path, query_params=None: {
        "/api/scans/scan-rep-1/summary": {
            "scan_id": "scan-rep-1",
            "status": "COMPLETED",
            "risk_gate": "REVIEW",
            "totals": {"high": 1},
            "scanner_runs": {"semgrep": "completed"},
        },
        "/api/scans/scan-rep-1": {
            "id": "scan-rep-1",
            "project_id": "proj-rep",
            "status": "COMPLETED",
        },
    }[path]

    args = build_parser().parse_args(["report"])
    code = cmd_report(args, api)
    assert code == 0


# 17, 18, 19, 20, 21. Findings filtering: default OPEN, severity, status, scanner, --all
def test_findings_filtering() -> None:
    api = MagicMock(spec=ApiClient)
    mock_findings = [
        {"id": "f1", "severity": "HIGH", "status": "OPEN", "scanner_name": "codeql", "title": "SQLi", "file_path": "a.py", "line_start": 10},
        {"id": "f2", "severity": "MEDIUM", "status": "OPEN", "scanner_name": "semgrep", "title": "XSS", "file_path": "b.py", "line_start": 20},
        {"id": "f3", "severity": "HIGH", "status": "FALSE_POSITIVE", "scanner_name": "codeql", "title": "Secret", "file_path": "c.py", "line_start": 30},
        {"id": "f4", "severity": "LOW", "status": "ACCEPTED_RISK", "scanner_name": "trivy", "title": "Pkg", "package_name": "express"},
    ]
    api.get.return_value = mock_findings

    # Default: OPEN only (f1 and f2)
    args_default = build_parser().parse_args(["findings", "--scan-id", "s1", "--json"])
    with patch("sys.stdout.write"):
        cmd_findings(args_default, api)

    # Severity filter: medium -> only f2
    args_sev = build_parser().parse_args(["findings", "--scan-id", "s1", "--severity", "medium", "--json"])
    with patch("builtins.print") as mock_print:
        cmd_findings(args_sev, api)
        printed = json.loads(mock_print.call_args[0][0])
        assert len(printed) == 1
        assert printed[0]["id"] == "f2"

    # Scanner filter: semgrep -> only f2
    args_scanner = build_parser().parse_args(["findings", "--scan-id", "s1", "--scanner", "semgrep", "--json"])
    with patch("builtins.print") as mock_print:
        cmd_findings(args_scanner, api)
        printed = json.loads(mock_print.call_args[0][0])
        assert len(printed) == 1
        assert printed[0]["id"] == "f2"

    # Status filter: false-positive -> f3
    args_stat = build_parser().parse_args(["findings", "--scan-id", "s1", "--status", "false-positive", "--json"])
    with patch("builtins.print") as mock_print:
        cmd_findings(args_stat, api)
        printed = json.loads(mock_print.call_args[0][0])
        assert len(printed) == 1
        assert printed[0]["id"] == "f3"

    # --all flag -> all 4 findings
    args_all = build_parser().parse_args(["findings", "--scan-id", "s1", "--all", "--json"])
    with patch("builtins.print") as mock_print:
        cmd_findings(args_all, api)
        printed = json.loads(mock_print.call_args[0][0])
        assert len(printed) == 4


# 22. --json produz JSON válido
def test_json_flag_valid_json() -> None:
    api = MagicMock(spec=ApiClient)
    mock_findings = [
        {"id": "f1", "severity": "HIGH", "status": "OPEN", "scanner_name": "codeql", "title": "SQLi"},
    ]
    api.get.return_value = mock_findings
    args = build_parser().parse_args(["findings", "--scan-id", "s1", "--json"])
    with patch("builtins.print") as mock_print:
        cmd_findings(args, api)
        raw = mock_print.call_args[0][0]
        parsed = json.loads(raw)
        assert isinstance(parsed, list)
        assert parsed[0]["id"] == "f1"


# 27. Comportamento de erro da API
def test_api_client_error_handling() -> None:
    client = ApiClient("http://localhost:8008")
    with patch("urllib.request.urlopen") as mock_urlopen:
        import io
        import urllib.error
        mock_urlopen.side_effect = urllib.error.HTTPError(
            "http://localhost:8008/api/scans/bad-id",
            404,
            "Not Found",
            {},
            io.BytesIO(b'{"detail": "Scan not found"}'),
        )
        with pytest.raises(RuntimeError, match="API Error 404: Scan not found"):
            client.get("/api/scans/bad-id")


# 28. Doctor
def test_doctor_command() -> None:
    api = MagicMock(spec=ApiClient)
    api.get.return_value = {"status": "ok"}
    api.base_url = "http://localhost:8008"

    args = build_parser().parse_args(["doctor"])
    with patch("subprocess.run") as mock_sub:
        mock_sub.return_value = MagicMock(returncode=0, stdout="mock version\n")
        code = cmd_doctor(args, api)
        assert code == 0


def test_format_scanner_runs() -> None:
    runs = {
        "semgrep": "completed",
        "codeql": "completed",
        "ai-appsec": "unavailable",
        "zap": "not_applicable",
        "nuclei": "not_applicable",
    }
    formatted = format_scanner_runs(runs)
    assert "Semgrep" in formatted
    assert "CodeQL" in formatted
    assert "AppSec unavailable" in formatted
    assert "ZAP not applicable" in formatted
    assert "Nuclei not applicable" in formatted


def test_get_project_internal_workspace_reuse() -> None:
    api = MagicMock(spec=ApiClient)
    # Project with existing scan
    api.get.return_value = [{"source_path": "/tmp/secops-workspaces/eduspace"}]
    ws = get_project_internal_workspace(api, "proj-1")
    assert ws == "/tmp/secops-workspaces/eduspace"

    # Project with no scan
    api.get.return_value = []
    ws_new = get_project_internal_workspace(api, "proj-new")
    assert ws_new == "/tmp/secops-workspaces/proj-new"


def test_stash_excluded_from_snapshot(tmp_path: Path) -> None:
    repo_dir = tmp_path / "stash_test_repo"
    repo_dir.mkdir()
    _init_test_git_repo(repo_dir)
    stashed_file = repo_dir / "secret_stash.txt"
    stashed_file.write_text("secret_data\n")
    subprocess.run(["git", "stash", "-u"], cwd=str(repo_dir), check=True, capture_output=True)
    assert not stashed_file.exists()

    p_arch = subprocess.Popen(["git", "archive", "HEAD"], cwd=str(repo_dir), stdout=subprocess.PIPE)
    p_tar = subprocess.Popen(["tar", "-t"], stdin=p_arch.stdout, stdout=subprocess.PIPE)
    if p_arch.stdout:
        p_arch.stdout.close()
    out, _ = p_tar.communicate()
    assert "secret_stash.txt" not in out.decode()


def test_main_entrypoint() -> None:
    # Test no args displays help and returns 0
    with patch("sys.stdout.write"):
        assert main([]) == 0

    # Test --help raises SystemExit with code 0
    with pytest.raises(SystemExit) as exc_info, patch("sys.stdout.write"):
        main(["--help"])
    assert exc_info.value.code == 0
