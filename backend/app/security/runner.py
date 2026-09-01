"""Secure subprocess runner for scanner execution.

All external tool invocations MUST go through this module.
"""
from __future__ import annotations

import asyncio
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path

from app.core.config import get_settings

logger = logging.getLogger(__name__)


class RunnerSecurityError(Exception):
    pass


class RunnerTimeoutError(Exception):
    pass


@dataclass
class RunResult:
    return_code: int
    stdout: str
    stderr: str
    timed_out: bool = False


@dataclass
class RunnerConfig:
    timeout: int = 300
    max_output_bytes: int = 50 * 1024 * 1024
    allowed_roots: list[Path] = field(default_factory=list)
    env_override: dict[str, str] = field(default_factory=dict)


def validate_path(path: Path, allowed_roots: list[Path]) -> Path:
    """Resolve and validate a path is within allowed roots.

    Prevents path traversal, directory escape, and symlink escape.
    """
    resolved = path.resolve()
    if not allowed_roots:
        return resolved
    for root in allowed_roots:
        try:
            resolved.relative_to(root.resolve())
            return resolved
        except ValueError:
            continue
    raise RunnerSecurityError(
        f"Path {resolved} is not within allowed roots: {[str(r) for r in allowed_roots]}"
    )


def validate_command(argv: list[str]) -> None:
    """Validate command arguments are safe."""
    if not argv:
        raise RunnerSecurityError("Empty command")
    dangerous = set(";&|`$\n\r\x00")
    for arg in argv:
        if not isinstance(arg, str):
            raise RunnerSecurityError(f"Non-string argument: {arg!r}")
        if any(c in dangerous for c in arg):
            raise RunnerSecurityError(f"Dangerous characters in argument: {arg!r}")


async def run_command(
    argv: list[str],
    cwd: Path | None = None,
    config: RunnerConfig | None = None,
) -> RunResult:
    """Execute a command securely as a subprocess.

    - Never uses shell=True
    - Validates all arguments
    - Enforces timeouts and output limits
    - Validates working directory against path traversal / symlinks
    - Cleans unsafe environment variables
    """
    if config is None:
        settings = get_settings()
        config = RunnerConfig(
            timeout=settings.scanner_timeout,
            max_output_bytes=settings.scanner_max_output_bytes,
            allowed_roots=[settings.allowed_workspace_root],
        )

    validate_command(argv)

    if cwd is not None:
        cwd = validate_path(cwd, config.allowed_roots)
        if not cwd.is_dir():
            raise RunnerSecurityError(f"Working directory does not exist: {cwd}")

    env = os.environ.copy()
    # Strip potentially dangerous env vars
    for key in ("LD_PRELOAD", "LD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES"):
        env.pop(key, None)
    env.update(config.env_override)

    logger.info("Running command: %s in %s", argv, cwd)

    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(cwd) if cwd else None,
            env=env,
        )
    except FileNotFoundError:
        return RunResult(return_code=-1, stdout="", stderr=f"Command not found: {argv[0]}")
    except PermissionError:
        return RunResult(return_code=-1, stdout="", stderr=f"Permission denied: {argv[0]}")

    try:
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            proc.communicate(), timeout=config.timeout
        )
    except TimeoutError:
        proc.kill()
        await proc.wait()
        return RunResult(return_code=-1, stdout="", stderr="Command timed out", timed_out=True)

    stdout = stdout_bytes[: config.max_output_bytes].decode("utf-8", errors="replace")
    stderr = stderr_bytes[: config.max_output_bytes].decode("utf-8", errors="replace")

    return RunResult(
        return_code=proc.returncode if proc.returncode is not None else 0,
        stdout=stdout,
        stderr=stderr,
    )
