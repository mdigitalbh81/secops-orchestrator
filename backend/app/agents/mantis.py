"""Google Mantis agentic security adapter and ingestion contract."""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from app.agents.base import (
    AgentCapability,
    AgentExecutionMode,
    AgenticSecurityAdapter,
)
from app.core.config import get_settings
from app.models.enums import EvidenceLevel, FindingStatus, Severity
from app.scanners.base import (
    NormalizedFinding,
    compute_fingerprint,
    compute_normalized_fingerprint,
)

logger = logging.getLogger(__name__)

UPSTREAM_REPO = "https://github.com/google/mantis"
DEFAULT_REVISION = "d13c93fb8e9779801711daea0d65fffa133c3b2d"
LICENSE = "Apache-2.0"
INTEGRATION_TYPE = "skills_and_contracts"

# Safe analysis capabilities permitted for future integration
PERMITTED_SAFE_CAPABILITIES: frozenset[AgentCapability] = frozenset(
    {
        AgentCapability.ARCHITECTURE,
        AgentCapability.THREAT_MODEL,
        AgentCapability.PLAN,
        AgentCapability.RESEARCH,
        AgentCapability.REVIEW,
        AgentCapability.CRITIC,
        AgentCapability.REPORT,
    }
)

# Explicitly blocked dangerous capabilities
BLOCKED_CAPABILITIES: frozenset[AgentCapability] = frozenset(
    {
        AgentCapability.REPRODUCE,
        AgentCapability.CHAIN,
        AgentCapability.PATCH,
    }
)


class MantisAdapter(AgenticSecurityAdapter):
    """Google Mantis security workflow and capability adapter.

    Implements contract boundary and result ingestion for Google Mantis.
    Active reproduction, exploit chaining, and automated patching are
    explicitly blocked in this phase.
    """

    UPSTREAM_REPO = UPSTREAM_REPO
    DEFAULT_REVISION = DEFAULT_REVISION
    LICENSE = LICENSE
    INTEGRATION_TYPE = INTEGRATION_TYPE

    @property
    def name(self) -> str:
        return "mantis"

    @property
    def version(self) -> str:
        return "0.1.0-contract"

    @property
    def revision(self) -> str:
        settings = get_settings()
        return settings.mantis_revision or DEFAULT_REVISION

    @property
    def capabilities(self) -> set[AgentCapability]:
        """Return only allowed safe capabilities.

        Dangerous capabilities (reproduce, chain, patch) are strictly blocked
        even if requested or set in environment variables.
        """
        return set(PERMITTED_SAFE_CAPABILITIES)

    @property
    def execution_mode(self) -> AgentExecutionMode:
        settings = get_settings()
        mode_str = (settings.mantis_execution_mode or "disabled").lower()
        try:
            return AgentExecutionMode(mode_str)
        except ValueError:
            return AgentExecutionMode.DISABLED

    async def is_available(self) -> bool:
        """Mantis CLI / execution runtime is not bundled or auto-installed."""
        return False

    def is_enabled(self) -> bool:
        """Disabled by default; requires explicit SECOPS_MANTIS_ENABLED=true."""
        settings = get_settings()
        return bool(settings.mantis_enabled)

    def ingest_findings(self, raw_data: Any) -> list[NormalizedFinding]:
        """Ingest Mantis finding schema objects into NormalizedFinding model.

        Accepts a single finding dictionary, a list of finding dictionaries,
        a wrapping dictionary {"findings": [...]}, or a JSON string of any of these.

        Safety invariants:
        1. EvidenceLevel is strictly SINGLE_SOURCE. Never RUNTIME_VALIDATED.
        2. Confidence is bounded between 0.20 and 0.60 (default 0.45).
        3. Source agent provenance is preserved.
        """
        items = self._extract_raw_items(raw_data)
        normalized: list[NormalizedFinding] = []

        for item in items:
            if not isinstance(item, dict):
                continue
            finding = self._normalize_single_item(item)
            if finding is not None:
                normalized.append(finding)

        return normalized

    def _extract_raw_items(self, raw_data: Any) -> list[dict]:
        if isinstance(raw_data, str):
            raw_data = raw_data.strip()
            if not raw_data:
                return []
            try:
                raw_data = json.loads(raw_data)
            except Exception:
                logger.warning("Failed to decode Mantis raw JSON payload")
                return []

        if isinstance(raw_data, dict):
            if "findings" in raw_data and isinstance(raw_data["findings"], list):
                return raw_data["findings"]
            return [raw_data]

        if isinstance(raw_data, list):
            return raw_data

        return []

    def _normalize_single_item(self, item: dict) -> NormalizedFinding | None:
        title = str(item.get("title") or "").strip()
        if not title:
            return None

        description = str(item.get("description") or "").strip()
        impact = str(item.get("impact") or "").strip()
        mitigation = str(item.get("mitigation") or "").strip()

        desc_parts = [description]
        if impact:
            desc_parts.append(f"Impact: {impact}")
        if mitigation:
            desc_parts.append(f"Mitigation: {mitigation}")
        full_description = "\n\n".join(p for p in desc_parts if p)

        # Severity mapping
        raw_sev = str(item.get("severity") or "UNKNOWN").upper().strip()
        try:
            severity = Severity(raw_sev)
        except ValueError:
            severity = Severity.UNKNOWN

        # Confidence calculation (bounded between 0.20 and 0.60)
        raw_conf = item.get("confidence")
        if isinstance(raw_conf, (int, float)):
            confidence = max(0.20, min(0.60, float(raw_conf)))
        else:
            confidence = 0.45

        # CWE extraction and normalization
        raw_cwe = item.get("cwe")
        cwe: str | None = None
        if raw_cwe:
            s_cwe = str(raw_cwe).strip()
            cwe_match = re.search(r"(?:cwe[/-]?)?(\d+)", s_cwe, re.IGNORECASE)
            if cwe_match and cwe_match.group(1):
                cwe = f"CWE-{int(cwe_match.group(1))}"
            else:
                cwe = s_cwe.upper() if s_cwe.lower().startswith("cwe") else s_cwe

        # CVE
        raw_cve = item.get("cve")
        cve = str(raw_cve).strip().upper() if raw_cve else None

        # Code paths extraction
        file_path: str | None = None
        line_start: int | None = None
        line_end: int | None = None

        if item.get("file_path"):
            file_path = str(item["file_path"]).strip()
            line_start = item.get("line_start")
            line_end = item.get("line_end")
        elif item.get("code_paths") and isinstance(item["code_paths"], list) and item["code_paths"]:
            first_path = str(item["code_paths"][0]).strip()
            file_path, line_start, line_end = self._parse_code_path(first_path)

        # Invariant: safe-analysis findings are NEVER RUNTIME_VALIDATED
        evidence_level = EvidenceLevel.SINGLE_SOURCE

        raw_fp = compute_fingerprint(
            scanner=self.name,
            cve=cve,
            cwe=cwe,
            file_path=file_path,
            line_start=line_start,
            title=title,
        )
        norm_fp = compute_normalized_fingerprint(
            cve=cve,
            cwe=cwe,
            file_path=file_path,
            title=title,
        )

        provenance = {
            "source_agent": self.name,
            "source_revision": self.revision,
            "raw_finding": item,
        }

        return NormalizedFinding(
            title=title,
            description=full_description,
            severity=severity,
            confidence=confidence,
            scanner_name=self.name,
            cwe=cwe,
            cve=cve,
            file_path=file_path,
            line_start=line_start,
            line_end=line_end,
            evidence_level=evidence_level,
            raw_data=provenance,
            raw_fingerprint=raw_fp,
            normalized_fingerprint=norm_fp,
            evidences=[provenance],
            status=FindingStatus.OPEN,
        )

    def _parse_code_path(self, code_path: str) -> tuple[str | None, int | None, int | None]:
        """Parse strings like 'src/auth.c:145' or 'app/main.py:10-25'."""
        if not code_path:
            return None, None, None

        parts = code_path.split(":", 1)
        path = parts[0].strip() or None
        if len(parts) == 1:
            return path, None, None

        lines_part = parts[1].strip()
        if "-" in lines_part:
            start_s, end_s = lines_part.split("-", 1)
            try:
                return path, int(start_s), int(end_s)
            except ValueError:
                pass

        try:
            return path, int(lines_part), None
        except ValueError:
            return path, None, None
