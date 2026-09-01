import sys
from pathlib import Path

import pytest

from app.security.runner import (
    RunnerConfig,
    RunnerSecurityError,
    run_command,
    validate_command,
    validate_path,
)


def test_validate_command_safe():
    validate_command(["semgrep", "scan", "--json", "/tmp/project"])
    validate_command(["npm", "audit", "--json"])


def test_validate_command_empty():
    with pytest.raises(RunnerSecurityError, match="Empty command"):
        validate_command([])


def test_validate_command_non_string():
    with pytest.raises(RunnerSecurityError, match="Non-string argument"):
        validate_command(["ls", 123])  # type: ignore


@pytest.mark.parametrize(
    "bad_arg",
    [
        "foo; rm -rf /",
        "foo && bar",
        "foo | bar",
        "`whoami`",
        "$(whoami)",
        "foo\nbar",
        "foo\rbar",
        "foo\x00bar",
    ],
)
def test_validate_command_dangerous_characters(bad_arg: str):
    with pytest.raises(RunnerSecurityError, match="Dangerous characters"):
        validate_command(["scanner", bad_arg])


def test_validate_path_allowed(tmp_path: Path):
    sub = tmp_path / "subdir"
    sub.mkdir()
    resolved = validate_path(sub, [tmp_path])
    assert resolved == sub.resolve()


def test_validate_path_traversal_blocked(tmp_path: Path):
    outside = tmp_path / ".." / "etc"
    with pytest.raises(RunnerSecurityError, match="not within allowed roots"):
        validate_path(outside, [tmp_path])


def test_validate_path_symlink_escape_blocked(tmp_path: Path):
    root = tmp_path / "allowed_root"
    root.mkdir()
    secret = tmp_path / "secret"
    secret.mkdir()

    # Create symlink inside root pointing outside
    symlink = root / "symlink_escape"
    symlink.symlink_to(secret)

    with pytest.raises(RunnerSecurityError, match="not within allowed roots"):
        validate_path(symlink, [root])


async def test_run_command_basic(tmp_path: Path):
    result = await run_command(
        [sys.executable, "-c", "print('hello secops')"],
        cwd=tmp_path,
        config=RunnerConfig(timeout=5, allowed_roots=[tmp_path]),
    )
    assert result.return_code == 0
    assert "hello secops" in result.stdout
    assert not result.timed_out


async def test_run_command_not_found(tmp_path: Path):
    result = await run_command(
        ["nonexistent_scanner_bin_12345"],
        cwd=tmp_path,
        config=RunnerConfig(timeout=5, allowed_roots=[tmp_path]),
    )
    assert result.return_code == -1
    assert "Command not found" in result.stderr


async def test_run_command_timeout(tmp_path: Path):
    result = await run_command(
        [sys.executable, "-c", "while True: pass"],
        cwd=tmp_path,
        config=RunnerConfig(timeout=1, allowed_roots=[tmp_path]),
    )
    assert result.timed_out
    assert result.return_code == -1
    assert "Command timed out" in result.stderr


async def test_run_command_max_output(tmp_path: Path):
    result = await run_command(
        [sys.executable, "-c", "print('A' * 10000)"],
        cwd=tmp_path,
        config=RunnerConfig(timeout=5, max_output_bytes=50, allowed_roots=[tmp_path]),
    )
    assert len(result.stdout) == 50
