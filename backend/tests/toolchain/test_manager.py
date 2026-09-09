from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from app.toolchain.manager import (
    ToolchainManager,
    compare_versions,
    parse_semantic_version,
)
from app.toolchain.models import ToolCategory, ToolInfo, ToolStatus


def test_parse_semantic_version() -> None:
    assert parse_semantic_version("semgrep 1.70.0") == "1.70.0"
    assert parse_semantic_version("v3.3.2") == "3.3.2"
    assert parse_semantic_version("pip-audit 2.7.3") == "2.7.3"
    assert parse_semantic_version("invalid") is None
    assert parse_semantic_version("") is None


def test_compare_versions() -> None:
    assert compare_versions("1.0.0", "1.0.0") == 0
    assert compare_versions("1.0.0", "1.1.0") == -1
    assert compare_versions("2.0.0", "1.9.9") == 1
    assert compare_versions("3.3.2", "v3.11.1") == -1
    assert compare_versions("v10.4.8", "10.4.8") == 0
    assert compare_versions(None, "1.0.0") is None
    assert compare_versions("1.0.0", None) is None


def test_tool_info_to_dict_serialization() -> None:
    info = ToolInfo(
        name="Semgrep",
        category=ToolCategory.ENGINE,
        installed_version="1.70.0",
        configured_version="unpinned",
        available_version="1.75.0",
        source="pypi",
        update_policy="manual",
        availability="available",
        status=ToolStatus.UPDATE_AVAILABLE,
        notes="Test note",
    )
    data = info.to_dict()
    assert data["name"] == "Semgrep"
    assert data["category"] == "ENGINE"
    assert data["status"] == "UPDATE_AVAILABLE"
    assert data["installed_version"] == "1.70.0"
    # Verifies standard JSON serialization without errors
    serialized = json.dumps(data)
    assert "UPDATE_AVAILABLE" in serialized


def test_detect_configured_versions_from_files(tmp_path: Path) -> None:
    docker_dir = tmp_path / "docker"
    docker_dir.mkdir()
    (docker_dir / "Dockerfile.worker").write_text(
        "ARG NUCLEI_VERSION=v3.5.0\nARG NUCLEI_TEMPLATES_VERSION=v10.6.0\n",
        encoding="utf-8",
    )
    (tmp_path / "docker-compose.yml").write_text(
        "image: zaproxy/zap-stable:2.18.0\n",
        encoding="utf-8",
    )

    mgr = ToolchainManager(repo_root=tmp_path)
    cfg = mgr.detect_configured_versions()

    assert cfg["nuclei"] == "3.5.0"
    assert cfg["nuclei_templates"] == "10.6.0"
    assert cfg["zap"] == "2.18.0"
    assert cfg["semgrep"] == "unpinned"
    assert cfg["codeql"] == "external (optional)"
    assert cfg["mantis"] == "disabled (contract only)"


def test_run_safe_tool_command_timeout() -> None:
    mgr = ToolchainManager()
    with (
        patch("shutil.which", return_value="/usr/bin/mock_tool"),
        patch("subprocess.run", side_effect=pytest.importorskip("subprocess").TimeoutExpired("cmd", 5)),
    ):
        rc, stdout, stderr = mgr.run_safe_tool_command(["mock_tool", "--version"])
        assert rc == -1
        assert "timed out" in stderr.lower()


def test_run_safe_tool_command_missing() -> None:
    mgr = ToolchainManager()
    with (
        patch("shutil.which", return_value=None),
        patch.object(mgr, "is_worker_running", return_value=False),
    ):
        rc, stdout, stderr = mgr.run_safe_tool_command(["nonexistent_tool", "--version"])
        assert rc == -1
        assert "not found" in stderr.lower()


def test_get_inventory_offline_default() -> None:
    mgr = ToolchainManager()
    with (
        patch.object(mgr, "detect_semgrep", return_value=("1.70.0", None)),
        patch.object(mgr, "detect_codeql", return_value=(None, "CodeQL not present")),
        patch.object(mgr, "detect_trivy", return_value=("0.54.0", None)),
        patch.object(mgr, "detect_pip_audit", return_value=("2.7.0", None)),
        patch.object(mgr, "detect_npm", return_value=("9.2.0", None)),
        patch.object(mgr, "detect_nuclei", return_value=("3.3.2", None)),
        patch.object(mgr, "detect_zap", return_value=("2.17.0", None)),
        patch.object(mgr, "detect_nuclei_templates", return_value=("10.4.8", None)),
        patch.object(mgr, "detect_trivy_db", return_value=("v2", None)),
    ):
        inventory = mgr.get_inventory(check_upstream=False)

    names = [t.name for t in inventory]
    assert "Semgrep" in names
    assert "CodeQL" in names
    assert "Trivy" in names
    assert "pip-audit" in names
    assert "npm" in names
    assert "Nuclei" in names
    assert "ZAP" in names
    assert "Nuclei Templates" in names
    assert "Trivy DB" in names
    assert "Mantis" in names

    # Offline status checks: installed tools have status UNKNOWN (no upstream checked)
    by_name = {t.name: t for t in inventory}
    assert by_name["Semgrep"].status == ToolStatus.UNKNOWN
    assert by_name["Semgrep"].installed_version == "1.70.0"
    assert by_name["Semgrep"].available_version is None

    # CodeQL remains OPTIONAL when not installed
    assert by_name["CodeQL"].status == ToolStatus.OPTIONAL
    assert by_name["CodeQL"].installed_version is None

    # Mantis is OPTIONAL and disabled
    assert by_name["Mantis"].status == ToolStatus.OPTIONAL
    assert by_name["Mantis"].installed_version is None


def test_get_inventory_with_upstream_updates() -> None:
    mgr = ToolchainManager()
    with (
        patch.object(mgr, "detect_semgrep", return_value=("1.70.0", None)),
        patch.object(mgr, "detect_nuclei", return_value=("3.3.2", None)),
        patch.object(mgr, "detect_codeql", return_value=("2.19.0", None)),
        patch.object(mgr, "check_upstream_version") as mock_check,
    ):
        def side_effect(tool_id: str) -> str | None:
            if tool_id == "semgrep":
                return "1.75.0"  # Update available
            if tool_id == "nuclei":
                return "3.3.2"   # Current
            return None

        mock_check.side_effect = side_effect
        inventory = mgr.get_inventory(check_upstream=True)

    by_name = {t.name: t for t in inventory}
    assert by_name["Semgrep"].status == ToolStatus.UPDATE_AVAILABLE
    assert by_name["Semgrep"].available_version == "1.75.0"

    assert by_name["Nuclei"].status == ToolStatus.CURRENT
    assert by_name["Nuclei"].available_version == "3.3.2"

    assert by_name["CodeQL"].status == ToolStatus.CURRENT
    assert by_name["CodeQL"].installed_version == "2.19.0"


def test_check_upstream_version_graceful_network_failure() -> None:
    mgr = ToolchainManager()
    with patch("urllib.request.urlopen", side_effect=OSError("Network unreachable")):
        ver = mgr.check_upstream_version("semgrep")
        assert ver is None
