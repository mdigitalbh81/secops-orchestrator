from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from app.agents.mantis_runtime import SAFE_SKILLS
from app.cli import main
from app.core.config import Settings, override_settings


def create_fake_mantis_root(tmp_path: Path) -> tuple[Path, str]:
    """Create a temporary fake Mantis repository with valid git commit and safe skills."""
    root = tmp_path / "fake_mantis"
    root.mkdir(parents=True, exist_ok=True)

    subprocess.run(["git", "init"], cwd=root, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Mantis Tester"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.email", "mantis@test.local"], cwd=root, check=True)

    for skill_rel in SAFE_SKILLS.values():
        skill_path = root / skill_rel
        skill_path.parent.mkdir(parents=True, exist_ok=True)
        skill_path.write_text(f"# Skill {skill_rel}\nInstructions for safe analysis.\n", encoding="utf-8")

    subprocess.run(["git", "add", "."], cwd=root, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "Initial Mantis checkout"], cwd=root, check=True, capture_output=True)

    res = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, check=True, capture_output=True, text=True)
    rev = res.stdout.strip()
    return root, rev


def create_fake_target(tmp_path: Path) -> Path:
    """Create a temporary target repository with source files."""
    target = tmp_path / "fake_target"
    target.mkdir(parents=True, exist_ok=True)
    (target / "main.py").write_text("def hello():\n    return 'world'\n", encoding="utf-8")
    (target / "utils.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    return target


def test_cli_mantis_help(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["mantis"])
    assert code == 0
    captured = capsys.readouterr()
    assert "status" in captured.out
    assert "analyze" in captured.out


def test_cli_mantis_status_human(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["mantis", "status"])
    assert code == 0
    captured = capsys.readouterr()
    assert "Google Mantis Safe Analysis Runtime" in captured.out
    assert "Enabled:" in captured.out
    assert "Pipeline Enabled:" in captured.out
    assert "Safe Capabilities:" in captured.out
    assert "Blocked Capabilities:" in captured.out
    assert "reproduce, chain, patch" in captured.out


def test_cli_mantis_status_json(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["mantis", "status", "--json"])
    assert code == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert isinstance(data, dict)
    assert "enabled" in data
    assert "pipeline_enabled" in data
    assert "safe_capabilities" in data
    assert "blocked_capabilities" in data
    assert data["blocked_capabilities"] == ["reproduce", "chain", "patch"]
    assert "architecture" in data["safe_capabilities"]
    assert data["bundled"] is False


def test_cli_mantis_analyze_dry_run_human(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root, rev = create_fake_mantis_root(tmp_path)
    target = create_fake_target(tmp_path)

    override_settings(
        Settings(
            mantis_enabled=True,
            mantis_root=root,
            mantis_revision=rev,
            mantis_execution_mode="dry_run",
        )
    )
    try:
        code = main(["mantis", "analyze", str(target), "--capability", "review", "--dry-run"])
        assert code == 0
        captured = capsys.readouterr()
        assert "Mantis Safe Analysis Dry Run" in captured.out
        assert "Capability:" in captured.out
        assert "review" in captured.out
        assert "Provider Call:    False" in captured.out
    finally:
        override_settings(Settings())


def test_cli_mantis_analyze_dry_run_json(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root, rev = create_fake_mantis_root(tmp_path)
    target = create_fake_target(tmp_path)

    override_settings(
        Settings(
            mantis_enabled=True,
            mantis_root=root,
            mantis_revision=rev,
            mantis_execution_mode="dry_run",
        )
    )
    try:
        code = main(["mantis", "analyze", str(target), "--capability", "review", "--dry-run", "--json"])
        assert code == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert isinstance(data, dict)
        assert data["dry_run"] is True
        assert data["capability"] == "review"
        assert data["provider_call"] is False
        assert data["source_file_count"] == 2
    finally:
        override_settings(Settings())


@pytest.mark.parametrize("blocked", ["reproduce", "chain", "patch"])
def test_cli_mantis_analyze_blocked_capabilities(
    tmp_path: Path,
    blocked: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    target = create_fake_target(tmp_path)
    code = main(["mantis", "analyze", str(target), "--capability", blocked])
    assert code != 0
    captured = capsys.readouterr()
    assert f"Capability '{blocked}' is blocked by SecOps safe-analysis policy." in captured.err
    # Must never suggest any bypass flag
    assert "bypass" not in captured.err.lower()
