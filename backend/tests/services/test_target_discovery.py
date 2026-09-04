"""Tests for monorepo / multi-subproject target discovery."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.services.target_discovery import (
    _is_safe_path,
    discover_scan_targets,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "sample-monorepo"


@pytest.fixture
def monorepo(tmp_path: Path) -> Path:
    """Create a realistic monorepo layout in tmp_path."""
    root = tmp_path / "monorepo"
    root.mkdir()

    # backend
    backend = root / "backend"
    backend.mkdir()
    (backend / "requirements.txt").write_text("flask==2.3.0\n")
    (backend / "app.py").write_text("from flask import Flask\n")

    # frontend
    frontend = root / "frontend"
    frontend.mkdir()
    (frontend / "package.json").write_text('{"name": "frontend"}\n')
    src = frontend / "src"
    src.mkdir()
    (src / "app.js").write_text("console.log('hi');\n")

    # root-level Python file so semgrep/codeql see code
    (root / "setup.py").write_text("# setup\n")

    return root


@pytest.fixture
def monorepo_multi(tmp_path: Path) -> Path:
    """Monorepo with multiple package.json and requirements.txt."""
    root = tmp_path / "multi"
    root.mkdir()

    for sub in ("frontend", "admin"):
        d = root / sub
        d.mkdir()
        (d / "package.json").write_text(f'{{"name": "{sub}"}}\n')

    for sub in ("backend", "ml-service"):
        d = root / sub
        d.mkdir()
        (d / "requirements.txt").write_text("requests\n")

    return root


# ---------------------------------------------------------------------------
# Tests - basic discovery
# ---------------------------------------------------------------------------


def test_discover_monorepo_targets(monorepo: Path):
    targets = discover_scan_targets(monorepo)

    npm_targets = [t for t in targets if t.scanner_name == "npm-audit"]
    pip_targets = [t for t in targets if t.scanner_name == "pip-audit"]
    semgrep_targets = [t for t in targets if t.scanner_name == "semgrep"]
    codeql_targets = [t for t in targets if t.scanner_name == "codeql"]
    trivy_targets = [t for t in targets if t.scanner_name == "trivy"]
    appsec_targets = [t for t in targets if t.scanner_name == "ai-appsec"]

    # npm-audit should find frontend/package.json
    assert len(npm_targets) == 1
    assert npm_targets[0].path == (monorepo / "frontend").resolve()
    assert npm_targets[0].manifest_path == Path("frontend/package.json")

    # pip-audit should find backend/requirements.txt
    assert len(pip_targets) == 1
    assert pip_targets[0].path == (monorepo / "backend").resolve()
    assert pip_targets[0].manifest_path == Path("backend/requirements.txt")

    # Repository-level scanners: one target each at root
    assert len(semgrep_targets) == 1
    assert semgrep_targets[0].path == monorepo.resolve()

    assert len(codeql_targets) == 1
    assert codeql_targets[0].path == monorepo.resolve()

    assert len(trivy_targets) == 1
    assert trivy_targets[0].path == monorepo.resolve()

    assert len(appsec_targets) == 1
    assert appsec_targets[0].path == monorepo.resolve()


def test_discover_multiple_manifests(monorepo_multi: Path):
    targets = discover_scan_targets(monorepo_multi)

    npm_targets = [t for t in targets if t.scanner_name == "npm-audit"]
    pip_targets = [t for t in targets if t.scanner_name == "pip-audit"]

    # Should find both package.json files
    assert len(npm_targets) == 2
    npm_paths = {str(t.manifest_path) for t in npm_targets}
    assert "admin/package.json" in npm_paths
    assert "frontend/package.json" in npm_paths

    # Should find both requirements.txt
    assert len(pip_targets) == 2
    pip_paths = {str(t.manifest_path) for t in pip_targets}
    assert "backend/requirements.txt" in pip_paths
    assert "ml-service/requirements.txt" in pip_paths


# ---------------------------------------------------------------------------
# Tests - ignored directories
# ---------------------------------------------------------------------------


def test_node_modules_ignored(monorepo: Path):
    nm = monorepo / "frontend" / "node_modules" / "some-pkg"
    nm.mkdir(parents=True)
    (nm / "package.json").write_text('{"name": "some-pkg"}\n')

    targets = discover_scan_targets(monorepo)
    npm_targets = [t for t in targets if t.scanner_name == "npm-audit"]

    # node_modules/some-pkg/package.json must NOT appear as a target
    assert len(npm_targets) == 1
    assert "node_modules" not in str(npm_targets[0].manifest_path)


def test_venv_ignored(monorepo: Path):
    venv = monorepo / ".venv" / "lib"
    venv.mkdir(parents=True)
    (venv / "requirements.txt").write_text("something\n")

    targets = discover_scan_targets(monorepo)
    pip_targets = [t for t in targets if t.scanner_name == "pip-audit"]

    assert len(pip_targets) == 1
    assert ".venv" not in str(pip_targets[0].manifest_path)


# ---------------------------------------------------------------------------
# Tests - symlink escape blocked
# ---------------------------------------------------------------------------


def test_symlink_escape_blocked(tmp_path: Path):
    """Symlinks pointing outside the workspace root must not be followed."""
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "app.py").write_text("x = 1\n")

    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "package.json").write_text('{"name": "evil"}\n')

    # Create symlink workspace/evil -> outside
    link = workspace / "evil"
    link.symlink_to(outside)

    targets = discover_scan_targets(workspace)
    npm_targets = [t for t in targets if t.scanner_name == "npm-audit"]

    # The symlinked package.json must NOT appear
    assert len(npm_targets) == 0


# ---------------------------------------------------------------------------
# Tests - subproject outside allowed root rejected
# ---------------------------------------------------------------------------


def test_path_outside_root_rejected(tmp_path: Path):
    workspace = tmp_path / "ws"
    workspace.mkdir()

    assert _is_safe_path(workspace, workspace) is True

    outside = tmp_path / "other"
    outside.mkdir()
    assert _is_safe_path(outside, workspace) is False


# ---------------------------------------------------------------------------
# Tests - scanner applicability with monorepo
# ---------------------------------------------------------------------------


def test_npm_audit_detects_nested_package_json(monorepo: Path):
    from app.scanners.npm_audit import NpmAuditScanner

    scanner = NpmAuditScanner()
    # No package.json at root but one exists in frontend/
    assert scanner.detect_applicability(monorepo) is True


def test_pip_audit_detects_nested_requirements(monorepo: Path):
    from app.scanners.pip_audit import PipAuditScanner

    scanner = PipAuditScanner()
    # No requirements.txt at root but one exists in backend/
    assert scanner.detect_applicability(monorepo) is True


def test_trivy_applies_to_any_dir(monorepo: Path):
    from app.scanners.trivy import TrivyScanner

    scanner = TrivyScanner()
    # No Dockerfile at root, should still be applicable
    assert scanner.detect_applicability(monorepo) is True


def test_semgrep_still_applicable(monorepo: Path):
    from app.scanners.semgrep import SemgrepScanner

    scanner = SemgrepScanner()
    assert scanner.detect_applicability(monorepo) is True


def test_codeql_finds_python_and_js(monorepo: Path):
    from app.scanners.codeql import CodeQLScanner

    scanner = CodeQLScanner()
    assert scanner.detect_applicability(monorepo) is True
    langs = scanner.detect_languages(monorepo)
    assert "python" in langs
    assert "javascript" in langs


# ---------------------------------------------------------------------------
# Tests - finding path normalization
# ---------------------------------------------------------------------------


def test_findings_preserve_relative_paths(monorepo: Path):
    """Findings from subproject scans should have paths relative to repo root."""
    from app.services.orchestrator import _normalize_file_path

    workspace = monorepo.resolve()

    # Absolute path from a scanner
    abs_path = str(workspace / "frontend" / "src" / "app.js")
    result = _normalize_file_path(abs_path, workspace / "frontend", workspace)
    assert result == "frontend/src/app.js"

    # Relative path from scanner working in frontend/
    result = _normalize_file_path("src/app.js", workspace / "frontend", workspace)
    assert result == "frontend/src/app.js"

    # Already relative to root
    result = _normalize_file_path("backend/app.py", workspace, workspace)
    assert result == "backend/app.py"

    # None stays None
    assert _normalize_file_path(None, workspace, workspace) is None


# ---------------------------------------------------------------------------
# Tests - fixture-based discovery
# ---------------------------------------------------------------------------


def test_fixture_monorepo():
    """Verify the shipped sample-monorepo fixture produces correct targets."""
    if not FIXTURES_DIR.exists():
        pytest.skip("sample-monorepo fixture not found")

    targets = discover_scan_targets(FIXTURES_DIR)

    npm = [t for t in targets if t.scanner_name == "npm-audit"]
    pip = [t for t in targets if t.scanner_name == "pip-audit"]

    assert len(npm) == 1
    assert "frontend" in str(npm[0].manifest_path)

    assert len(pip) == 1
    assert "backend" in str(pip[0].manifest_path)


def test_applicability_single_source_consistency(tmp_path: Path):
    """Verify detect_applicability is 100% consistent with discover_scan_targets."""
    from app.scanners.npm_audit import NpmAuditScanner
    from app.scanners.pip_audit import PipAuditScanner

    npm_scanner = NpmAuditScanner()
    pip_scanner = PipAuditScanner()

    # Case 1: empty dir
    empty = tmp_path / "empty"
    empty.mkdir()
    targets = discover_scan_targets(empty)
    assert npm_scanner.detect_applicability(empty) == any(
        t.scanner_name == "npm-audit" for t in targets
    )
    assert pip_scanner.detect_applicability(empty) == any(
        t.scanner_name == "pip-audit" for t in targets
    )
    assert not npm_scanner.detect_applicability(empty)
    assert not pip_scanner.detect_applicability(empty)

    # Case 2: nested npm only
    nested_npm = tmp_path / "nested_npm"
    nested_npm.mkdir()
    (nested_npm / "sub").mkdir()
    (nested_npm / "sub" / "package.json").write_text("{}")
    targets = discover_scan_targets(nested_npm)
    assert npm_scanner.detect_applicability(nested_npm) == any(
        t.scanner_name == "npm-audit" for t in targets
    )
    assert pip_scanner.detect_applicability(nested_npm) == any(
        t.scanner_name == "pip-audit" for t in targets
    )
    assert npm_scanner.detect_applicability(nested_npm) is True
    assert pip_scanner.detect_applicability(nested_npm) is False

    # Case 3: nested pip only
    nested_pip = tmp_path / "nested_pip"
    nested_pip.mkdir()
    (nested_pip / "pkg").mkdir()
    (nested_pip / "pkg" / "requirements.txt").write_text("flask")
    targets = discover_scan_targets(nested_pip)
    assert npm_scanner.detect_applicability(nested_pip) == any(
        t.scanner_name == "npm-audit" for t in targets
    )
    assert pip_scanner.detect_applicability(nested_pip) == any(
        t.scanner_name == "pip-audit" for t in targets
    )
    assert npm_scanner.detect_applicability(nested_pip) is False
    assert pip_scanner.detect_applicability(nested_pip) is True
