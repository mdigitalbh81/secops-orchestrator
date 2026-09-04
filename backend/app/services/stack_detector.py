"""Detect which scanners are applicable to a given project directory."""

from __future__ import annotations

import logging
from pathlib import Path

from app.scanners.base import ScannerAdapter

logger = logging.getLogger(__name__)


async def detect_applicable_scanners(
    project_path: Path,
    scanners: list[ScannerAdapter],
    target_url: str | None = None,
) -> dict[str, dict]:
    """Return dict of scanner_name -> {applicable: bool, available: bool, scanner: adapter}.

    If a scanner is applicable but not available (binary missing), it will be
    reported so it does not block the overall scan.
    """
    result: dict[str, dict] = {}
    for scanner in scanners:
        applicable = scanner.detect_applicability(project_path, target_url=target_url)
        available = False
        if applicable:
            try:
                available = await scanner.is_available()
            except Exception:
                logger.exception("Error checking availability for %s", scanner.name)

        result[scanner.name] = {
            "applicable": applicable,
            "available": available,
            "scanner": scanner,
        }
        logger.info(
            "Scanner %s: applicable=%s, available=%s",
            scanner.name,
            applicable,
            available,
        )

    return result
