from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.models.enums import RiskGate, ScanStatus


class ScanCreate(BaseModel):
    project_id: str
    source_path: str
    target_url: str | None = None


class ScanResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    project_id: str
    source_path: str
    target_url: str | None = None
    status: ScanStatus
    risk_gate: RiskGate | None = None
    error_message: str | None = None
    created_at: datetime
    completed_at: datetime | None = None
