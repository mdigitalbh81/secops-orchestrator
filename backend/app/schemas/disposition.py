"""Disposition request/response schemas."""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, field_validator

from app.models.enums import FindingStatus, RiskGate


class DispositionRequest(BaseModel):
    status: FindingStatus
    justification: str
    actor: str
    expires_at: datetime | None = None

    @field_validator("justification")
    @classmethod
    def justification_not_blank(cls, v: str) -> str:
        if not v or not v.strip():
            msg = "justification must not be empty or whitespace-only"
            raise ValueError(msg)
        return v.strip()

    @field_validator("actor")
    @classmethod
    def actor_not_blank(cls, v: str) -> str:
        if not v or not v.strip():
            msg = "actor must not be empty or whitespace-only"
            raise ValueError(msg)
        return v.strip()


class DispositionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    finding_id: str
    status: FindingStatus
    justification: str
    actor: str
    expires_at: datetime | None = None
    updated_at: datetime
    scan_id: str
    scan_risk_gate: RiskGate | None = None


class DispositionEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    project_id: str
    scan_id: str | None = None
    finding_id: str | None = None
    scanner_name: str
    normalized_fingerprint: str
    previous_status: FindingStatus
    new_status: FindingStatus
    justification: str
    actor: str
    expires_at: datetime | None = None
    created_at: datetime


class CurrentDispositionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    project_id: str
    scanner_name: str
    normalized_fingerprint: str
    status: FindingStatus
    justification: str
    actor: str
    expires_at: datetime | None = None
    source_finding_id: str | None = None
    created_at: datetime
    updated_at: datetime
