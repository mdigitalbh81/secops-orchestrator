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
    cmd_codeql,
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
    parse_codeql_version,
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


# 30. CodeQL CLI commands and UX tests
def test_codeql_parser() -> None:
    """Test A: parser for secops codeql and secops codeql --json."""
    parser = build_parser()

    args_plain = parser.parse_args(["codeql"])
    assert args_plain.command == "codeql"
    assert args_plain.json is False

    args_json = parser.parse_args(["codeql", "--json"])
    assert args_json.command == "codeql"
    assert args_json.json is True


def test_codeql_version_parsing() -> None:
    """Defensive parsing for CodeQL CLI version."""
    assert parse_codeql_version('{"version": "2.19.0"}') == "2.19.0"
    assert parse_codeql_version('{"codeql_version": "2.18.1"}') == "2.18.1"
    assert parse_codeql_version("CodeQL command-line toolchain release 2.19.0.") == "2.19.0"
    assert parse_codeql_version("") is None


def test_codeql_available_worker(capsys: pytest.CaptureFixture[str]) -> None:
    """Test B: CodeQL available in worker exits 0 with expected human and json output."""
    api = MagicMock(spec=ApiClient)

    def mock_subprocess(argv: list[str], **kwargs: Any) -> MagicMock:
        if "ps" in argv:
            return MagicMock(returncode=0, stdout="worker_cid_123\n", stderr="")
        if "python" in argv:
            return MagicMock(returncode=0, stdout="/opt/secops-codeql/codeql\n", stderr="")
        if "codeql" in argv:
            return MagicMock(returncode=0, stdout=json.dumps({"version": "2.19.0"}), stderr="")
        return MagicMock(returncode=0, stdout="", stderr="")

    # Human output
    args_human = build_parser().parse_args(["codeql"])
    with patch("subprocess.run", side_effect=mock_subprocess):
        code = cmd_codeql(args_human, api)
    assert code == 0
    captured = capsys.readouterr()
    assert "GitHub CodeQL" in captured.out
    assert "Status:      AVAILABLE" in captured.out
    assert "Environment: SecOps worker" in captured.out
    assert "Version:     2.19.0" in captured.out
    assert "CodeQL is an optional third-party integration." in captured.out

    # JSON output
    args_json = build_parser().parse_args(["codeql", "--json"])
    with patch("subprocess.run", side_effect=mock_subprocess):
        code = cmd_codeql(args_json, api)
    assert code == 0
    captured_json = capsys.readouterr()
    data = json.loads(captured_json.out)
    assert data["scanner"] == "codeql"
    assert data["status"] == "available"
    assert data["environment"] == "worker"
    assert data["version"] == "2.19.0"
    assert data["distributed_by_secops"] is False
    assert "github.com" in data["terms_url"]
    assert "docs.github.com" in data["setup_url"]


def test_codeql_unavailable_worker(capsys: pytest.CaptureFixture[str]) -> None:
    """Test C: CodeQL unavailable in worker exits 0 with guidance."""
    api = MagicMock(spec=ApiClient)

    def mock_subprocess(argv: list[str], **kwargs: Any) -> MagicMock:
        if "ps" in argv:
            return MagicMock(returncode=0, stdout="worker_cid_123\n", stderr="")
        if "python" in argv:
            return MagicMock(returncode=0, stdout="", stderr="")
        return MagicMock(returncode=0, stdout="", stderr="")

    # Human output
    args_human = build_parser().parse_args(["codeql"])
    with patch("subprocess.run", side_effect=mock_subprocess):
        code = cmd_codeql(args_human, api)
        assert code == 0
        captured = capsys.readouterr()
        assert "GitHub CodeQL" in captured.out
        assert "Status:      NOT AVAILABLE" in captured.out
        assert "Environment: SecOps worker" in captured.out
        assert "1. Review GitHub's CodeQL Terms and Conditions:" in captured.out
        assert "2. Follow GitHub's official CodeQL installation documentation:" in captured.out
        assert "3. Make the CodeQL installation available inside the SecOps worker." in captured.out
        assert "4. Run: secops codeql" in captured.out
        assert "SecOps Orchestrator grants no rights to use CodeQL." in captured.out

    # JSON output
    args_json = build_parser().parse_args(["codeql", "--json"])
    with patch("subprocess.run", side_effect=mock_subprocess):
        code = cmd_codeql(args_json, api)
    assert code == 0
    captured_json = capsys.readouterr()
    data = json.loads(captured_json.out)
    assert data["scanner"] == "codeql"
    assert data["status"] == "unavailable"
    assert data["environment"] == "worker"
    assert data["version"] is None
    assert data["distributed_by_secops"] is False


def test_codeql_broken_worker(capsys: pytest.CaptureFixture[str]) -> None:
    """Test CodeQL present in worker but broken exits 1 with error status."""
    api = MagicMock(spec=ApiClient)

    def mock_subprocess(argv: list[str], **kwargs: Any) -> MagicMock:
        if "ps" in argv:
            return MagicMock(returncode=0, stdout="worker_cid_123\n", stderr="")
        if "python" in argv:
            return MagicMock(returncode=0, stdout="/opt/secops-codeql/codeql\n", stderr="")
        if "codeql" in argv:
            return MagicMock(
                returncode=1,
                stdout="",
                stderr="A fatal error occurred: Java not found\n",
            )
        return MagicMock(returncode=0, stdout="", stderr="")

    # Human output
    args_human = build_parser().parse_args(["codeql"])
    with patch("subprocess.run", side_effect=mock_subprocess):
        code = cmd_codeql(args_human, api)
    assert code == 1
    captured = capsys.readouterr()
    assert "GitHub CodeQL" in captured.out
    assert "Status:      ERROR" in captured.out
    assert "Environment: SecOps worker" in captured.out
    assert "CodeQL found in worker but not executed correctly." in captured.out
    assert "A fatal error occurred: Java not found" in captured.out
    assert "Verify CodeQL installation and run: secops codeql" in captured.out

    # JSON output
    args_json = build_parser().parse_args(["codeql", "--json"])
    with patch("subprocess.run", side_effect=mock_subprocess):
        code = cmd_codeql(args_json, api)
    assert code == 1
    captured_json = capsys.readouterr()
    data = json.loads(captured_json.out)
    assert data["scanner"] == "codeql"
    assert data["status"] == "error"
    assert data["environment"] == "worker"
    assert data["version"] is None
    assert data["distributed_by_secops"] is False
    assert data["error"] == "A fatal error occurred: Java not found"
    assert "terms_url" in data
    assert "setup_url" in data


def test_codeql_which_fails_is_error(capsys: pytest.CaptureFixture[str]) -> None:
    """Test that which returning non-zero is treated as error, not unavailable."""
    api = MagicMock(spec=ApiClient)

    def mock_subprocess(argv: list[str], **kwargs: Any) -> MagicMock:
        if "ps" in argv:
            return MagicMock(returncode=0, stdout="worker_cid_123\n", stderr="")
        if "python" in argv:
            return MagicMock(returncode=1, stdout="", stderr="container error\n")
        return MagicMock(returncode=0, stdout="", stderr="")

    args = build_parser().parse_args(["codeql"])
    with patch("subprocess.run", side_effect=mock_subprocess):
        code = cmd_codeql(args, api)
    assert code == 1
    captured = capsys.readouterr()
    assert "Status:      ERROR" in captured.out

    args_json = build_parser().parse_args(["codeql", "--json"])
    with patch("subprocess.run", side_effect=mock_subprocess):
        code = cmd_codeql(args_json, api)
    assert code == 1
    data = json.loads(capsys.readouterr().out)
    assert data["status"] == "error"


def test_codeql_which_timeout_is_error(capsys: pytest.CaptureFixture[str]) -> None:
    """Test that which timing out is treated as error, not unavailable."""
    api = MagicMock(spec=ApiClient)
    call_count = 0

    def mock_subprocess(argv: list[str], **kwargs: Any) -> MagicMock:
        nonlocal call_count
        if "ps" in argv:
            return MagicMock(returncode=0, stdout="worker_cid_123\n", stderr="")
        if "python" in argv:
            raise subprocess.TimeoutExpired(cmd="docker", timeout=10)
        return MagicMock(returncode=0, stdout="", stderr="")

    args = build_parser().parse_args(["codeql"])
    with patch("subprocess.run", side_effect=mock_subprocess):
        code = cmd_codeql(args, api)
    assert code == 1
    captured = capsys.readouterr()
    assert "Status:      ERROR" in captured.out


def test_codeql_docker_or_worker_broken(capsys: pytest.CaptureFixture[str]) -> None:
    """Test D: Docker/worker failure exits 1."""
    api = MagicMock(spec=ApiClient)
    args = build_parser().parse_args(["codeql"])

    # Worker not running
    with patch("subprocess.run", return_value=MagicMock(returncode=0, stdout="", stderr="")):
        code = cmd_codeql(args, api)
        assert code == 1
    captured = capsys.readouterr()
    assert "SecOps worker container is not running" in captured.err

    # Docker command error
    with patch("subprocess.run", return_value=MagicMock(returncode=1, stdout="", stderr="Docker daemon down")):
        code = cmd_codeql(args, api)
        assert code == 1

    # Docker binary not found
    with patch("subprocess.run", side_effect=FileNotFoundError):
        code = cmd_codeql(args, api)
        assert code == 1


def test_doctor_codeql_available(capsys: pytest.CaptureFixture[str]) -> None:
    """Test E: Doctor shows CodeQL available when detected in worker."""
    api = MagicMock(spec=ApiClient)
    api.get.return_value = {"status": "ok"}
    api.base_url = "http://localhost:8008"
    args = build_parser().parse_args(["doctor"])

    def mock_subprocess(argv: list[str], **kwargs: Any) -> MagicMock:
        if "python" in argv:
            return MagicMock(returncode=0, stdout="/opt/secops-codeql/codeql\n", stderr="")
        if "codeql" in argv:
            return MagicMock(returncode=0, stdout=json.dumps({"version": "2.19.0"}), stderr="")
        return MagicMock(returncode=0, stdout="cid_or_version\n", stderr="")

    with patch("subprocess.run", side_effect=mock_subprocess):
        code = cmd_doctor(args, api)
    assert code == 0
    captured = capsys.readouterr()
    assert "[✓] CodeQL: 2.19.0 (worker)" in captured.out


def test_doctor_codeql_absent_does_not_fail(capsys: pytest.CaptureFixture[str]) -> None:
    """Test F: Doctor reports CodeQL absent without failing doctor."""
    api = MagicMock(spec=ApiClient)
    api.get.return_value = {"status": "ok"}
    api.base_url = "http://localhost:8008"
    args = build_parser().parse_args(["doctor"])

    def mock_subprocess(argv: list[str], **kwargs: Any) -> MagicMock:
        if "python" in argv:
            return MagicMock(returncode=0, stdout="", stderr="")
        return MagicMock(returncode=0, stdout="cid_or_version\n", stderr="")

    with patch("subprocess.run", side_effect=mock_subprocess):
        code = cmd_doctor(args, api)
    assert code == 0
    captured = capsys.readouterr()
    assert "[○] CodeQL: optional, not available in worker" in captured.out
    assert "Run 'secops codeql' for setup guidance" in captured.out


def test_doctor_codeql_broken_does_not_fail(capsys: pytest.CaptureFixture[str]) -> None:
    """Test Doctor reports CodeQL broken without failing doctor."""
    api = MagicMock(spec=ApiClient)
    api.get.return_value = {"status": "ok"}
    api.base_url = "http://localhost:8008"
    args = build_parser().parse_args(["doctor"])

    def mock_subprocess(argv: list[str], **kwargs: Any) -> MagicMock:
        if "python" in argv:
            return MagicMock(returncode=0, stdout="/opt/secops-codeql/codeql\n", stderr="")
        if "codeql" in argv:
            return MagicMock(returncode=1, stdout="", stderr="codeql: JVM crash\n")
        return MagicMock(returncode=0, stdout="cid_or_version\n", stderr="")

    with patch("subprocess.run", side_effect=mock_subprocess):
        code = cmd_doctor(args, api)
    assert code == 0
    captured = capsys.readouterr()
    assert "[!] CodeQL: integration check failed" in captured.out
    assert "Run 'secops codeql' for details" in captured.out
    assert "not available" not in captured.out


def test_doctor_codeql_which_fails_is_error(capsys: pytest.CaptureFixture[str]) -> None:
    """Test Doctor treats which returning non-zero as integration error, not unavailable."""
    api = MagicMock(spec=ApiClient)
    api.get.return_value = {"status": "ok"}
    api.base_url = "http://localhost:8008"
    args = build_parser().parse_args(["doctor"])

    def mock_subprocess(argv: list[str], **kwargs: Any) -> MagicMock:
        if "python" in argv:
            return MagicMock(returncode=1, stdout="", stderr="container error\n")
        return MagicMock(returncode=0, stdout="cid_or_version\n", stderr="")

    with patch("subprocess.run", side_effect=mock_subprocess):
        code = cmd_doctor(args, api)
    assert code == 0
    captured = capsys.readouterr()
    assert "[!] CodeQL: integration check failed" in captured.out
    assert "not available" not in captured.out


def test_doctor_shows_valkey_service(capsys: pytest.CaptureFixture[str]) -> None:
    """Test G: Doctor displays 'Valkey' instead of 'Redis'."""
    api = MagicMock(spec=ApiClient)
    api.get.return_value = {"status": "ok"}
    api.base_url = "http://localhost:8008"
    args = build_parser().parse_args(["doctor"])

    with patch("subprocess.run", return_value=MagicMock(returncode=0, stdout="ok\n", stderr="")):
        code = cmd_doctor(args, api)
    assert code == 0
    captured = capsys.readouterr()
    assert "[✓] Valkey:" in captured.out
    assert "[✓] Redis:" not in captured.out


def test_audit_human_hint_when_codeql_unavailable(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Test H: Audit shows CodeQL setup hint in human report when CodeQL is unavailable."""
    repo_dir = tmp_path / "audit_hint_repo"
    repo_dir.mkdir()
    _init_test_git_repo(repo_dir)

    def mock_get(path: str, query_params: dict | None = None) -> Any:
        if path == "/api/projects":
            return [{"id": "pid-hint", "name": "audit_hint_repo"}]
        if path.startswith("/api/projects/pid-hint/scans"):
            return []
        if path == "/api/scans/sid-hint":
            return {"id": "sid-hint", "status": "COMPLETED", "risk_gate": "PASS"}
        if path == "/api/scans/sid-hint/summary":
            return {
                "scan_id": "sid-hint",
                "status": "COMPLETED",
                "risk_gate": "PASS",
                "totals": {},
                "scanner_runs": {"semgrep": "completed", "codeql": "unavailable"},
            }
        return {}

    api = MagicMock(spec=ApiClient)
    api.get.side_effect = mock_get
    api.post.return_value = {"id": "sid-hint"}

    with (
        patch("app.cli.deploy_snapshot"),
        patch("app.cli.preflight_check", return_value=(True, "OK")),
    ):
        args = build_parser().parse_args(["audit", str(repo_dir)])
        code = cmd_audit(args, api)
    assert code == 0
    captured = capsys.readouterr()
    assert "CodeQL is optional and not available in the worker. Run `secops codeql` for setup guidance." in captured.out


def test_audit_json_no_hint(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Test I: Audit with --json does not display human hint."""
    repo_dir = tmp_path / "audit_json_repo"
    repo_dir.mkdir()
    _init_test_git_repo(repo_dir)

    def mock_get(path: str, query_params: dict | None = None) -> Any:
        if path == "/api/projects":
            return [{"id": "pid-json", "name": "audit_json_repo"}]
        if path.startswith("/api/projects/pid-json/scans"):
            return []
        if path == "/api/scans/sid-json":
            return {"id": "sid-json", "status": "COMPLETED", "risk_gate": "PASS"}
        if path == "/api/scans/sid-json/summary":
            return {
                "scan_id": "sid-json",
                "status": "COMPLETED",
                "risk_gate": "PASS",
                "totals": {},
                "scanner_runs": {"semgrep": "completed", "codeql": "unavailable"},
            }
        return {}

    api = MagicMock(spec=ApiClient)
    api.get.side_effect = mock_get
    api.post.return_value = {"id": "sid-json"}

    with (
        patch("app.cli.deploy_snapshot"),
        patch("app.cli.preflight_check", return_value=(True, "OK")),
    ):
        args = build_parser().parse_args(["audit", str(repo_dir), "--json"])
        code = cmd_audit(args, api)
    assert code == 0
    captured = capsys.readouterr()
    assert "Run `secops codeql`" not in captured.out
    # Output must be valid json
    data = json.loads(captured.out)
    assert data["scan"]["status"] == "COMPLETED"


def test_audit_not_applicable_no_hint(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Test J: Audit with CodeQL not_applicable does not show hint."""
    repo_dir = tmp_path / "audit_na_repo"
    repo_dir.mkdir()
    _init_test_git_repo(repo_dir)

    def mock_get(path: str, query_params: dict | None = None) -> Any:
        if path == "/api/projects":
            return [{"id": "pid-na", "name": "audit_na_repo"}]
        if path.startswith("/api/projects/pid-na/scans"):
            return []
        if path == "/api/scans/sid-na":
            return {"id": "sid-na", "status": "COMPLETED", "risk_gate": "PASS"}
        if path == "/api/scans/sid-na/summary":
            return {
                "scan_id": "sid-na",
                "status": "COMPLETED",
                "risk_gate": "PASS",
                "totals": {},
                "scanner_runs": {"semgrep": "completed", "codeql": "not_applicable"},
            }
        return {}

    api = MagicMock(spec=ApiClient)
    api.get.side_effect = mock_get
    api.post.return_value = {"id": "sid-na"}

    with (
        patch("app.cli.deploy_snapshot"),
        patch("app.cli.preflight_check", return_value=(True, "OK")),
    ):
        args = build_parser().parse_args(["audit", str(repo_dir)])
        code = cmd_audit(args, api)
    assert code == 0
    captured = capsys.readouterr()
    assert "Run `secops codeql`" not in captured.out


def test_audit_completed_no_hint(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Test K: Audit with CodeQL completed does not show hint."""
    repo_dir = tmp_path / "audit_comp_repo"
    repo_dir.mkdir()
    _init_test_git_repo(repo_dir)

    def mock_get(path: str, query_params: dict | None = None) -> Any:
        if path == "/api/projects":
            return [{"id": "pid-comp", "name": "audit_comp_repo"}]
        if path.startswith("/api/projects/pid-comp/scans"):
            return []
        if path == "/api/scans/sid-comp":
            return {"id": "sid-comp", "status": "COMPLETED", "risk_gate": "PASS"}
        if path == "/api/scans/sid-comp/summary":
            return {
                "scan_id": "sid-comp",
                "status": "COMPLETED",
                "risk_gate": "PASS",
                "totals": {},
                "scanner_runs": {"semgrep": "completed", "codeql": "completed"},
            }
        return {}

    api = MagicMock(spec=ApiClient)
    api.get.side_effect = mock_get
    api.post.return_value = {"id": "sid-comp"}

    with (
        patch("app.cli.deploy_snapshot"),
        patch("app.cli.preflight_check", return_value=(True, "OK")),
    ):
        args = build_parser().parse_args(["audit", str(repo_dir)])
        code = cmd_audit(args, api)
    assert code == 0
    captured = capsys.readouterr()
    assert "Run `secops codeql`" not in captured.out
