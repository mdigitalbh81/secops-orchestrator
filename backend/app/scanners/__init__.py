from app.scanners.base import NormalizedFinding, ScannerAdapter
from app.scanners.npm_audit import NpmAuditScanner
from app.scanners.pip_audit import PipAuditScanner
from app.scanners.semgrep import SemgrepScanner
from app.scanners.trivy import TrivyScanner


def get_all_scanners() -> list[ScannerAdapter]:
    """Return all registered scanner adapters."""
    return [
        SemgrepScanner(),
        NpmAuditScanner(),
        PipAuditScanner(),
        TrivyScanner(),
    ]


__all__ = [
    "ScannerAdapter",
    "NormalizedFinding",
    "SemgrepScanner",
    "NpmAuditScanner",
    "PipAuditScanner",
    "TrivyScanner",
    "get_all_scanners",
]
