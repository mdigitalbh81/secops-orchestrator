"""Base scanner adapter interface.

Every scanner adapter must subclass ScannerAdapter and implement all abstract methods.
The orchestrator interacts only through this interface so scanner-specific
details are confined to each adapter module.
"""

from __future__ import annotations

import hashlib
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

from app.models.enums import EvidenceLevel, FindingStatus, Severity
from app.security.runner import RunnerConfig, RunResult, run_command

logger = logging.getLogger(__name__)


@dataclass
class NormalizedFinding:
    title: str
    description: str
    severity: Severity
    confidence: float
    scanner_name: str
    cwe: str | None = None
    cve: str | None = None
    file_path: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    package_name: str | None = None
    installed_version: str | None = None
    fixed_version: str | None = None
    url: str | None = None
    evidence_level: EvidenceLevel = EvidenceLevel.SINGLE_SOURCE
    raw_data: dict | None = None
    raw_fingerprint: str = ""
    normalized_fingerprint: str = ""
    evidences: list[dict] = field(default_factory=list)
    status: FindingStatus = FindingStatus.OPEN

    def __post_init__(self) -> None:
        if not self.evidences and self.raw_data is not None:
            self.evidences = [self.raw_data]


def compute_fingerprint(
    scanner: str,
    cve: str | None = None,
    cwe: str | None = None,
    package_name: str | None = None,
    file_path: str | None = None,
    line_start: int | None = None,
    title: str = "",
    url: str | None = None,
) -> str:
    """Deterministic scanner-specific raw fingerprint."""
    parts = [scanner]
    if cve:
        parts.append(f"cve:{cve}")
    if cwe:
        parts.append(f"cwe:{cwe}")
    if package_name:
        parts.append(f"pkg:{package_name}")
    if file_path:
        parts.append(f"file:{file_path}")
    if line_start is not None:
        parts.append(f"line:{line_start}")
    if url:
        parts.append(f"url:{url}")
    if not cve and not cwe and not package_name and not file_path and not url:
        parts.append(f"title:{title}")
    return "|".join(parts)


def compute_normalized_fingerprint(
    cve: str | None = None,
    cwe: str | None = None,
    package_name: str | None = None,
    file_path: str | None = None,
    title: str = "",
    url: str | None = None,
) -> str:
    """Scanner-agnostic fingerprint for cross-scanner deduplication."""
    parts: list[str] = []
    if cve:
        parts.append(f"cve:{cve.strip().upper()}")
        if package_name:
            parts.append(f"pkg:{package_name.strip().lower()}")
        elif file_path:
            parts.append(f"file:{file_path.strip()}")
        elif url:
            parts.append(f"url:{url.strip()}")
    elif cwe:
        parts.append(f"cwe:{cwe.strip().upper()}")
        if package_name:
            parts.append(f"pkg:{package_name.strip().lower()}")
        elif file_path:
            parts.append(f"file:{file_path.strip()}")
        elif url:
            parts.append(f"url:{url.strip()}")
        else:
            parts.append(f"title:{title.strip().lower()}")
    elif package_name:
        parts.append(f"pkg:{package_name.strip().lower()}")
        parts.append(f"title:{title.strip().lower()}")
    elif file_path:
        parts.append(f"file:{file_path.strip()}")
        parts.append(f"title:{title.strip().lower()}")
    elif url:
        parts.append(f"url:{url.strip()}")
        parts.append(f"title:{title.strip().lower()}")
    else:
        parts.append(f"title:{title.strip().lower()}")

    raw = "|".join(parts)
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


class ScannerAdapter(ABC):
    """Abstract base for all scanner integrations."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique scanner identifier, e.g. \x27semgrep\x27."""

    @abstractmethod
    async def is_available(self) -> bool:
        """Check if the scanner binary/tool is installed and callable."""

    @abstractmethod
    def detect_applicability(self, project_path: Path, target_url: str | None = None) -> bool:
        """Return True if the scanner applies to the given project / target."""

    @abstractmethod
    def build_command(self, project_path: Path, target_url: str | None = None) -> list[str]:
        """Return argv list to execute scanner."""

    async def execute(
        self,
        project_path: Path,
        target_url: str | None = None,
        config: RunnerConfig | None = None,
    ) -> RunResult:
        """Run scanner through secure runner."""
        argv = self.build_command(project_path, target_url=target_url)
        return await run_command(argv, cwd=project_path, config=config)

    @abstractmethod
    def parse_result(self, result: RunResult) -> list[dict]:
        """Parse raw output into a list of raw finding dicts."""

    @abstractmethod
    def normalize_findings(self, raw_findings: list[dict]) -> list[NormalizedFinding]:
        """Convert raw findings to NormalizedFinding instances."""
