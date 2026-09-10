"""Agent registry and lookup mechanisms."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.agents.base import AgenticSecurityAdapter

from app.agents.mantis import MantisAdapter

DEFAULT_AGENTS: dict[str, type[AgenticSecurityAdapter]] = {
    "mantis": MantisAdapter,
}

_REGISTRY: dict[str, type[AgenticSecurityAdapter]] = dict(DEFAULT_AGENTS)


def register_agent(cls: type[AgenticSecurityAdapter]) -> type[AgenticSecurityAdapter]:
    """Decorator / helper to register an agent adapter class."""
    instance = cls()
    _REGISTRY[instance.name] = cls
    return cls


def get_agent(name: str) -> AgenticSecurityAdapter | None:
    """Get an agent adapter instance by name."""
    cls = _REGISTRY.get(name)
    if cls is None:
        return None
    return cls()


def get_all_agents() -> list[AgenticSecurityAdapter]:
    """Instantiate and return all registered agent adapters."""
    return [cls() for cls in _REGISTRY.values()]


def clear_registry() -> None:
    """Clear registered agents (testing helper)."""
    _REGISTRY.clear()


def reset_registry() -> None:
    """Reset registry to default agent adapters."""
    _REGISTRY.clear()
    _REGISTRY.update(DEFAULT_AGENTS)
