from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.models.enums import EvidenceLevel, FindingStatus, Severity
from app.schemas.finding import FindingResponse


class CorrelationGroupResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    scan_id: str
    canonical_title: str
    canonical_cwe: str | None = None
    canonical_cve: str | None = None
    severity: Severity
    confidence: float
    evidence_level: EvidenceLevel
    status: FindingStatus
    remediation_recommendation: str | None = None
    created_at: datetime
    findings: list[FindingResponse] = []
