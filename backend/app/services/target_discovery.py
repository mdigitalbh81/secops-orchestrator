"""Recursive scan target discovery for monorepos and multi-subproject repos.

Walks the workspace directory to find manifests (package.json, requirements.txt,
pyproject.toml, Dockerfile, etc.) and produces a list of ScanTarget objects that
tell each scanner *where* and *what* to scan.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

# Directories that must never be traversed during discovery.
IGNORED_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        "node_modules",
        ".venv",
        "venv",
        "dist",
        "build",
        "coverage",
        "__pycache__",
        ".cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        ".mypy_cache",
        "trivy_cache",
    }
)

# Safety limits to avoid resource exhaustion on huge repos.
MAX_DEPTH = 10
MAX_TARGETS_PER_MANIFEST = 50


@dataclass(frozen=True)
class ScanTarget:
    """A concrete location where a scanner should run."""

    path: Path  # directory to use as cwd / scan root
    scanner_name: str
    target_type: str  # e.g. "repository", "npm-subproject", "pip-subproject"
    manifest_path: Path | None = None  # relative to workspace root
    language: str | None = None
    metadata: dict = field(default_factory=dict)


def _is_safe_path(candidate: Path, workspace_root: Path) -> bool:
    """Ensure *candidate* does not escape *workspace_root* via symlinks."""
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(workspace_root.resolve(strict=True))
        return True
    except (ValueError, OSError):
        return False


def _walk_safe(
    root: Path,
    workspace_root: Path,
    *,
    current_depth: int = 0,
) -> list[Path]:
    """Return file paths under *root*, respecting IGNORED_DIRS, depth, and symlink safety."""
    if current_depth > MAX_DEPTH:
        return []
    if not _is_safe_path(root, workspace_root):
        return []

    results: list[Path] = []
    try:
        entries = sorted(root.iterdir())
    except PermissionError:
        return results

    for entry in entries:
        if entry.name in IGNORED_DIRS:
            continue
        if entry.is_symlink() and not _is_safe_path(entry, workspace_root):
            continue
        if entry.is_file():
            results.append(entry)
        elif entry.is_dir():
            results.extend(
                _walk_safe(entry, workspace_root, current_depth=current_depth + 1)
            )
    return results


def discover_scan_targets(workspace_root: Path) -> list[ScanTarget]:
    """Discover all scan targets inside *workspace_root*.

    Returns targets for every scanner that needs per-subproject handling
    (npm-audit, pip-audit) plus repository-level targets for scanners that
    always operate at the root (semgrep, codeql, trivy, ai-appsec).
    """
    workspace_root = workspace_root.resolve()
    files = _walk_safe(workspace_root, workspace_root)

    targets: list[ScanTarget] = []

    # --- npm-audit: one target per package.json --------------------------
    npm_count = 0
    for f in files:
        if f.name == "package.json" and npm_count < MAX_TARGETS_PER_MANIFEST:
            targets.append(
                ScanTarget(
                    path=f.parent,
                    scanner_name="npm-audit",
                    target_type="npm-subproject",
                    manifest_path=f.relative_to(workspace_root),
                )
            )
            npm_count += 1

    # --- pip-audit: one target per requirements.txt / pyproject.toml -----
    pip_count = 0
    for f in files:
        if f.name in ("requirements.txt", "pyproject.toml") and pip_count < MAX_TARGETS_PER_MANIFEST:
            targets.append(
                ScanTarget(
                    path=f.parent,
                    scanner_name="pip-audit",
                    target_type="pip-subproject",
                    manifest_path=f.relative_to(workspace_root),
                )
            )
            pip_count += 1

    # --- Repository-level scanners ---------------------------------------
    for scanner_name, target_type in (
        ("semgrep", "repository"),
        ("codeql", "repository"),
        ("trivy", "repository"),
        ("ai-appsec", "repository"),
    ):
        targets.append(
            ScanTarget(
                path=workspace_root,
                scanner_name=scanner_name,
                target_type=target_type,
            )
        )

    return targets
