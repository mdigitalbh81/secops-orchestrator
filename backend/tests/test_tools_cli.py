from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from app.cli import main
from app.toolchain.models import ToolCategory, ToolInfo, ToolStatus


def test_cli_tools_help(capsys) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["tools", "--help"])
    assert excinfo.value.code == 0
    captured = capsys.readouterr()
    assert "Inspect security toolchain" in captured.out


def test_cli_tools_check_help(capsys) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["tools", "check", "--help"])
    assert excinfo.value.code == 0
    captured = capsys.readouterr()
    assert "Check upstream for available tool updates" in captured.out


def test_cli_tools_human_output(capsys) -> None:
    mock_tools = [
        ToolInfo(
            name="Semgrep",
            category=ToolCategory.ENGINE,
            installed_version="1.70.0",
            configured_version="unpinned",
            available_version=None,
            source="pypi",
            update_policy="manual",
            availability="available",
            status=ToolStatus.UNKNOWN,
        ),
        ToolInfo(
            name="Mantis",
            category=ToolCategory.AGENT,
            installed_version=None,
            configured_version="disabled (contract only)",
            available_version="d13c93fb",
            source="google/mantis",
            update_policy="manual contract",
            availability="contract_only",
            status=ToolStatus.OPTIONAL,
        ),
    ]

    with patch("app.toolchain.manager.ToolchainManager.get_inventory", return_value=mock_tools):
        rc = main(["tools"])
        assert rc == 0
        captured = capsys.readouterr()
        assert "TOOL" in captured.out
        assert "CATEGORY" in captured.out
        assert "INSTALLED" in captured.out
        assert "Semgrep" in captured.out
        assert "1.70.0" in captured.out
        assert "Mantis" in captured.out
        assert "OPTIONAL" in captured.out


def test_cli_tools_json_output(capsys) -> None:
    mock_tools = [
        ToolInfo(
            name="Nuclei",
            category=ToolCategory.ENGINE,
            installed_version="3.3.2",
            configured_version="3.3.2",
            available_version=None,
            source="binary",
            update_policy="pinned",
            availability="available",
            status=ToolStatus.UNKNOWN,
        ),
    ]

    with patch("app.toolchain.manager.ToolchainManager.get_inventory", return_value=mock_tools):
        rc = main(["tools", "--json"])
        assert rc == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]["name"] == "Nuclei"
        assert data[0]["category"] == "ENGINE"
        assert data[0]["installed_version"] == "3.3.2"


def test_cli_tools_check_with_updates(capsys) -> None:
    mock_tools = [
        ToolInfo(
            name="Semgrep",
            category=ToolCategory.ENGINE,
            installed_version="1.70.0",
            configured_version="unpinned",
            available_version="1.75.0",
            source="pypi",
            update_policy="manual",
            availability="available",
            status=ToolStatus.UPDATE_AVAILABLE,
        ),
    ]

    with patch("app.toolchain.manager.ToolchainManager.get_inventory", return_value=mock_tools) as mock_get:
        rc = main(["tools", "check"])
        assert rc == 0
        mock_get.assert_called_once_with(check_upstream=True)
        captured = capsys.readouterr()
        assert "UPDATE_AVAILABLE" in captured.out
        assert "1.75.0" in captured.out


def test_cli_tools_check_json_output(capsys) -> None:
    mock_tools = [
        ToolInfo(
            name="Semgrep",
            category=ToolCategory.ENGINE,
            installed_version="1.70.0",
            configured_version="unpinned",
            available_version="1.75.0",
            source="pypi",
            update_policy="manual",
            availability="available",
            status=ToolStatus.UPDATE_AVAILABLE,
        ),
    ]

    with patch("app.toolchain.manager.ToolchainManager.get_inventory", return_value=mock_tools):
        rc = main(["tools", "check", "--json"])
        assert rc == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert isinstance(data, list)
        assert data[0]["status"] == "UPDATE_AVAILABLE"
        assert data[0]["available_version"] == "1.75.0"


def test_cli_tools_check_offline_graceful_degradation(capsys) -> None:
    mock_tools = [
        ToolInfo(
            name="Semgrep",
            category=ToolCategory.ENGINE,
            installed_version="1.70.0",
            configured_version="unpinned",
            available_version=None,
            source="pypi",
            update_policy="manual",
            availability="available",
            status=ToolStatus.UNKNOWN,
        ),
    ]

    with patch("app.toolchain.manager.ToolchainManager.get_inventory", return_value=mock_tools):
        rc = main(["tools", "check"])
        assert rc == 0
        captured = capsys.readouterr()
        assert "UNKNOWN" in captured.out
