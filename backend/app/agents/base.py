"""Base agentic security adapter interfaces and capability models."""

from __future__ import annotations

import enum
from abc import ABC, abstractmethod
from typing import Any

from app.scanners.base import NormalizedFinding


class AgentCapability(enum.StrEnum):
    """Individual agent capabilities across security lifecycle stages."""

    ARCHITECTURE = "architecture"
    THREAT_MODEL = "threat_model"
    PLAN = "plan"
    RESEARCH = "research"
    REVIEW = "review"
    CRITIC = "critic"
    REPRODUCE = "reproduce"
    CHAIN = "chain"
    PATCH = "patch"
    REPORT = "report"


class CapabilityClass(enum.StrEnum):
    """Risk/impact classification for agent capabilities."""

    SAFE_ANALYSIS = "SAFE_ANALYSIS"
    ACTIVE_REPRODUCTION = "ACTIVE_REPRODUCTION"
    PATCH_GENERATION = "PATCH_GENERATION"


CAPABILITY_CLASS_MAP: dict[AgentCapability, CapabilityClass] = {
    AgentCapability.ARCHITECTURE: CapabilityClass.SAFE_ANALYSIS,
    AgentCapability.THREAT_MODEL: CapabilityClass.SAFE_ANALYSIS,
    AgentCapability.PLAN: CapabilityClass.SAFE_ANALYSIS,
    AgentCapability.RESEARCH: CapabilityClass.SAFE_ANALYSIS,
    AgentCapability.REVIEW: CapabilityClass.SAFE_ANALYSIS,
    AgentCapability.CRITIC: CapabilityClass.SAFE_ANALYSIS,
    AgentCapability.REPORT: CapabilityClass.SAFE_ANALYSIS,
    AgentCapability.REPRODUCE: CapabilityClass.ACTIVE_REPRODUCTION,
    AgentCapability.CHAIN: CapabilityClass.ACTIVE_REPRODUCTION,
    AgentCapability.PATCH: CapabilityClass.PATCH_GENERATION,
}


class AgentExecutionMode(enum.StrEnum):
    """Execution environment boundary mode for agent."""

    DISABLED = "disabled"
    SANDBOX = "sandbox"
    LOCAL = "local"
    DRY_RUN = "dry_run"


class AgenticSecurityAdapter(ABC):
    """Abstract base adapter for agentic security engines."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique agent identifier."""

    @property
    @abstractmethod
    def version(self) -> str:
        """Agent software / contract version."""

    @property
    @abstractmethod
    def revision(self) -> str:
        """Upstream git revision / commit hash."""

    @property
    @abstractmethod
    def capabilities(self) -> set[AgentCapability]:
        """Set of permitted capabilities for this adapter instance."""

    @property
    @abstractmethod
    def execution_mode(self) -> AgentExecutionMode:
        """Execution isolation mode."""

    @abstractmethod
    async def is_available(self) -> bool:
        """Check if agent runner/dependencies are installed or accessible."""

    @abstractmethod
    def is_enabled(self) -> bool:
        """Check if agent is enabled via configuration."""

    def has_capability(self, capability: AgentCapability) -> bool:
        """Verify whether specific capability is declared and allowed."""
        return capability in self.capabilities

    def capability_classes(self) -> set[CapabilityClass]:
        """Return unique capability classes represented by declared capabilities."""
        return {
            CAPABILITY_CLASS_MAP[cap]
            for cap in self.capabilities
            if cap in CAPABILITY_CLASS_MAP
        }

    def is_safe_analysis_only(self) -> bool:
        """Return True if adapter declares only safe read/analysis capabilities."""
        classes = self.capability_classes()
        return bool(classes) and classes == {CapabilityClass.SAFE_ANALYSIS}

    def allows_active_reproduction(self) -> bool:
        """Check if adapter enables active reproduction capabilities."""
        return CapabilityClass.ACTIVE_REPRODUCTION in self.capability_classes()

    def allows_patch_generation(self) -> bool:
        """Check if adapter enables automated patch generation."""
        return CapabilityClass.PATCH_GENERATION in self.capability_classes()

    @abstractmethod
    def ingest_findings(self, raw_data: Any) -> list[NormalizedFinding]:
        """Parse and ingest raw agent findings into standard NormalizedFinding format."""
