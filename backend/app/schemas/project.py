from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class ProjectCreate(BaseModel):
    name: str
    repository_url: str | None = None
    description: str | None = None


class ProjectResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    repository_url: str | None = None
    description: str | None = None
    created_at: datetime
    updated_at: datetime
