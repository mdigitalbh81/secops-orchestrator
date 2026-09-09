"""Security toolchain inventory data models."""

from __future__ import annotations

import enum
from dataclasses import asdict, dataclass
from typing import Any


class ToolCategory(enum.StrEnum):
    """Category of toolchain component."""

    ENGINE = "ENGINE"
    KNOWLEDGE = "KNOWLEDGE"
    AGENT = "AGENT"


class ToolStatus(enum.StrEnum):
    """Health and version status of tool."""

    CURRENT = "CURRENT"
    UPDATE_AVAILABLE = "UPDATE_AVAILABLE"
    NOT_INSTALLED = "NOT_INSTALLED"
    OPTIONAL = "OPTIONAL"
    UNKNOWN = "UNKNOWN"
    ERROR = "ERROR"


@dataclass
class ToolInfo:
    """Structured inventory entry for a toolchain component."""

    name: str
    category: ToolCategory
    installed_version: str | None
    configured_version: str | None
    available_version: str | None
    source: str
    update_policy: str
    availability: str
    status: ToolStatus
    notes: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize ToolInfo into JSON-compatible dictionary."""
        data = asdict(self)
        data["category"] = self.category.value
        data["status"] = self.status.value
        return data
