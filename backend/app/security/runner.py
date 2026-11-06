"""Secure subprocess runner for scanner execution.

All external tool invocations MUST go through this module.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

from app.core.config import get_settings

logger = logging.getLogger(__name__)


class RunnerSecurityError(Exception):
    pass


class RunnerTimeoutError(Exception):
    pass


SECRET_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"-----BEGIN (?:[A-Z ]*?)PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z ]*?)PRIVATE KEY-----"),
    re.compile(r"eyJ[A-Za-z0-9-_=]{10,}\.[A-Za-z0-9-_=]{10,}(?:\.[A-Za-z0-9-_.+/=]*)?"),
    re.compile(r"(?i)(?:api[_-]?key|secret|password|passwd|auth[_-]?token|bearer)\s*[:=]\s*['\"][a-zA-Z0-9_\-.~+/=]{8,}['\"]"),
]


def redact_secrets(text: str) -> str:
    """Mask sensitive tokens, secrets, private keys, passwords."""
    redacted = text
    for pattern in SECRET_PATTERNS:
        redacted = pattern.sub("[REDACTED_SECRET]", redacted)
    return redacted



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


_UNSAFE_ENV_KEYS = ("LD_PRELOAD", "LD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES")


def _build_env(overrides: dict[str, str]) -> dict[str, str]:
    env = os.environ.copy()
    env.update(overrides)
    # Always scrub after overrides, which must not re-enable loader injection.
    for key in _UNSAFE_ENV_KEYS:
        env.pop(key, None)
    return env


def _validate_output_limit(limit: int) -> None:
    if limit < 0:
        raise RunnerSecurityError("max_output_bytes must be non-negative")


async def _drain_bounded_async(stream: asyncio.StreamReader, limit: int) -> bytes:
    """Drain to EOF without retaining more than limit bytes in memory."""
    chunks: list[bytes] = []
    retained = 0
    while chunk := await stream.read(65536):
        remaining = limit - retained
        if remaining > 0:
            kept = chunk[:remaining]
            chunks.append(kept)
            retained += len(kept)
    return b"".join(chunks)


def _drain_bounded_sync(stream, limit: int) -> bytes:
    chunks: list[bytes] = []
    retained = 0
    while chunk := stream.read(65536):
        remaining = limit - retained
        if remaining > 0:
            kept = chunk[:remaining]
            chunks.append(kept)
            retained += len(kept)
    return b"".join(chunks)


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
    _validate_output_limit(config.max_output_bytes)

    if cwd is not None:
        cwd = validate_path(cwd, config.allowed_roots)
        if not cwd.is_dir():
            raise RunnerSecurityError(f"Working directory does not exist: {cwd}")

    env = _build_env(config.env_override)

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
        stdout_bytes, stderr_bytes, _ = await asyncio.wait_for(
            asyncio.gather(
                _drain_bounded_async(proc.stdout, config.max_output_bytes),
                _drain_bounded_async(proc.stderr, config.max_output_bytes),
                proc.wait(),
            ),
            timeout=config.timeout,
        )
    except (TimeoutError, asyncio.CancelledError) as exc:
        if proc.returncode is None:
            proc.kill()
        await proc.wait()
        if isinstance(exc, asyncio.CancelledError):
            raise
        return RunResult(return_code=-1, stdout="", stderr="Command timed out", timed_out=True)

    return RunResult(
        return_code=proc.returncode if proc.returncode is not None else 0,
        stdout=stdout_bytes.decode("utf-8", errors="replace"),
        stderr=stderr_bytes.decode("utf-8", errors="replace"),
    )


def run_command_sync(
    argv: list[str],
    cwd: Path | None = None,
    config: RunnerConfig | None = None,
) -> RunResult:
    """Execute a command synchronously and securely in a subprocess.

    Enforces the same invariants as run_command:
    no shell=True, validated arguments, timeouts, output limits, sanitized environment.
    """
    if config is None:
        settings = get_settings()
        config = RunnerConfig(
            timeout=settings.scanner_timeout,
            max_output_bytes=settings.scanner_max_output_bytes,
            allowed_roots=[settings.allowed_workspace_root] if settings.allowed_workspace_root else [],
        )

    validate_command(argv)
    _validate_output_limit(config.max_output_bytes)

    if cwd is not None:
        cwd = validate_path(cwd, config.allowed_roots)
        if not cwd.is_dir():
            raise RunnerSecurityError(f"Working directory does not exist: {cwd}")

    env = _build_env(config.env_override)

    logger.info("Running sync command: %s (cwd=%s)", argv, cwd)
    try:
        proc = subprocess.Popen(  # noqa: S603
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(cwd) if cwd else None,
            env=env,
        )
    except FileNotFoundError:
        return RunResult(return_code=-1, stdout="", stderr=f"Command not found: {argv[0]}")
    except PermissionError:
        return RunResult(return_code=-1, stdout="", stderr=f"Permission denied: {argv[0]}")

    with ThreadPoolExecutor(max_workers=2) as pool:
        stdout_future = pool.submit(_drain_bounded_sync, proc.stdout, config.max_output_bytes)
        stderr_future = pool.submit(_drain_bounded_sync, proc.stderr, config.max_output_bytes)
        try:
            proc.wait(timeout=config.timeout)
        except subprocess.TimeoutExpired:
            if proc.poll() is None:
                proc.kill()
            proc.wait()
            return RunResult(return_code=-1, stdout="", stderr="Command timed out", timed_out=True)
        stdout_bytes = stdout_future.result()
        stderr_bytes = stderr_future.result()
        proc.stdout.close()
        proc.stderr.close()
        return RunResult(
            return_code=proc.returncode if proc.returncode is not None else 0,
            stdout=stdout_bytes.decode("utf-8", errors="replace"),
            stderr=stderr_bytes.decode("utf-8", errors="replace"),
        )
