"""Scanner registry and exports."""

from app.scanners.ai_appsec import AiAppSecScanner
from app.scanners.base import NormalizedFinding, ScannerAdapter
from app.scanners.codeql import CodeQLScanner
from app.scanners.npm_audit import NpmAuditScanner
from app.scanners.nuclei import NucleiScanner
from app.scanners.pip_audit import PipAuditScanner
from app.scanners.semgrep import SemgrepScanner
from app.scanners.trivy import TrivyScanner
from app.scanners.zap import ZapScanner


def get_all_scanners() -> list[ScannerAdapter]:
    """Return all registered scanner adapters."""
    return [
        SemgrepScanner(),
        CodeQLScanner(),
        NpmAuditScanner(),
        PipAuditScanner(),
        TrivyScanner(),
        AiAppSecScanner(),
        ZapScanner(),
        NucleiScanner(),
    ]


__all__ = [
    "AiAppSecScanner",
    "CodeQLScanner",
    "NormalizedFinding",
    "NpmAuditScanner",
    "NucleiScanner",
    "PipAuditScanner",
    "ScannerAdapter",
    "SemgrepScanner",
    "TrivyScanner",
    "ZapScanner",
    "get_all_scanners",
]
