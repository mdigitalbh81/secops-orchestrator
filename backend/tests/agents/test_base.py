from __future__ import annotations

from typing import Any

from app.agents.base import (
    AgentCapability,
    AgentExecutionMode,
    AgenticSecurityAdapter,
    CapabilityClass,
)
from app.agents.registry import (
    clear_registry,
    get_agent,
    get_all_agents,
    register_agent,
    reset_registry,
)
from app.scanners.base import NormalizedFinding


class DummySafeAgent(AgenticSecurityAdapter):
    @property
    def name(self) -> str:
        return "dummy-safe"

    @property
    def version(self) -> str:
        return "0.1.0"

    @property
    def revision(self) -> str:
        return "abc1234"

    @property
    def capabilities(self) -> set[AgentCapability]:
        return {
            AgentCapability.ARCHITECTURE,
            AgentCapability.THREAT_MODEL,
            AgentCapability.PLAN,
            AgentCapability.RESEARCH,
            AgentCapability.REVIEW,
            AgentCapability.CRITIC,
            AgentCapability.REPORT,
        }

    @property
    def execution_mode(self) -> AgentExecutionMode:
        return AgentExecutionMode.DISABLED

    async def is_available(self) -> bool:
        return False

    def is_enabled(self) -> bool:
        return False

    def ingest_findings(self, raw_data: Any) -> list[NormalizedFinding]:
        return []


class DummyDangerousAgent(AgenticSecurityAdapter):
    @property
    def name(self) -> str:
        return "dummy-dangerous"

    @property
    def version(self) -> str:
        return "0.2.0"

    @property
    def revision(self) -> str:
        return "def5678"

    @property
    def capabilities(self) -> set[AgentCapability]:
        return {
            AgentCapability.REVIEW,
            AgentCapability.REPRODUCE,
            AgentCapability.CHAIN,
            AgentCapability.PATCH,
        }

    @property
    def execution_mode(self) -> AgentExecutionMode:
        return AgentExecutionMode.SANDBOX

    async def is_available(self) -> bool:
        return True

    def is_enabled(self) -> bool:
        return True

    def ingest_findings(self, raw_data: Any) -> list[NormalizedFinding]:
        return []


def test_safe_agent_capabilities() -> None:
    agent = DummySafeAgent()
    assert agent.name == "dummy-safe"
    assert agent.version == "0.1.0"
    assert agent.revision == "abc1234"
    assert agent.has_capability(AgentCapability.REVIEW)
    assert not agent.has_capability(AgentCapability.REPRODUCE)
    assert agent.is_safe_analysis_only()
    assert not agent.allows_active_reproduction()
    assert not agent.allows_patch_generation()
    assert agent.capability_classes() == {CapabilityClass.SAFE_ANALYSIS}


def test_dangerous_agent_capabilities() -> None:
    agent = DummyDangerousAgent()
    assert agent.name == "dummy-dangerous"
    assert not agent.is_safe_analysis_only()
    assert agent.allows_active_reproduction()
    assert agent.allows_patch_generation()
    assert agent.capability_classes() == {
        CapabilityClass.SAFE_ANALYSIS,
        CapabilityClass.ACTIVE_REPRODUCTION,
        CapabilityClass.PATCH_GENERATION,
    }


def test_agent_registry() -> None:
    clear_registry()
    assert get_all_agents() == []
    assert get_agent("nonexistent") is None

    register_agent(DummySafeAgent)
    agent = get_agent("dummy-safe")
    assert agent is not None
    assert agent.name == "dummy-safe"
    assert len(get_all_agents()) == 1
    clear_registry()
    reset_registry()
