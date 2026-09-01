from pathlib import Path
from unittest.mock import AsyncMock

from app.scanners.npm_audit import NpmAuditScanner
from app.scanners.pip_audit import PipAuditScanner
from app.scanners.semgrep import SemgrepScanner
from app.scanners.trivy import TrivyScanner
from app.services.stack_detector import detect_applicable_scanners


async def test_detect_applicable_scanners_all(tmp_path: Path):
    (tmp_path / "package.json").write_text("{}")
    (tmp_path / "requirements.txt").write_text("flask")
    (tmp_path / "Dockerfile").write_text("FROM python:3.12")

    scanners = [
        SemgrepScanner(),
        NpmAuditScanner(),
        PipAuditScanner(),
        TrivyScanner(),
    ]

    # Mock is_available to return True
    for s in scanners:
        s.is_available = AsyncMock(return_value=True)

    detection = await detect_applicable_scanners(tmp_path, scanners)

    assert detection["semgrep"]["applicable"] is True
    assert detection["semgrep"]["available"] is True

    assert detection["npm-audit"]["applicable"] is True
    assert detection["npm-audit"]["available"] is True

    assert detection["pip-audit"]["applicable"] is True
    assert detection["pip-audit"]["available"] is True

    assert detection["trivy"]["applicable"] is True
    assert detection["trivy"]["available"] is True


async def test_detect_applicable_scanners_unavailable(tmp_path: Path):
    (tmp_path / "package.json").write_text("{}")

    npm_scanner = NpmAuditScanner()
    npm_scanner.is_available = AsyncMock(return_value=False)

    detection = await detect_applicable_scanners(tmp_path, [npm_scanner])
    assert detection["npm-audit"]["applicable"] is True
    assert detection["npm-audit"]["available"] is False


async def test_detect_applicable_scanners_not_applicable(tmp_path: Path):
    # Empty folder - npm-audit should not be applicable (no package.json anywhere)
    npm_scanner = NpmAuditScanner()
    detection = await detect_applicable_scanners(tmp_path, [npm_scanner])
    assert detection["npm-audit"]["applicable"] is False
    assert detection["npm-audit"]["available"] is False
