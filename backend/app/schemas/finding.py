from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.models.enums import EvidenceLevel, FindingStatus, Severity


class FindingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    scan_id: str
    scanner_name: str
    title: str
    description: str | None = None
    severity: Severity
    confidence: float
    evidence_level: EvidenceLevel = EvidenceLevel.SINGLE_SOURCE
    correlation_group_id: str | None = None
    cwe: str | None = None
    cve: str | None = None
    file_path: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    package_name: str | None = None
    installed_version: str | None = None
    fixed_version: str | None = None
    url: str | None = None
    raw_fingerprint: str
    normalized_fingerprint: str
    status: FindingStatus
    created_at: datetime


class EvidenceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    finding_id: str
    scanner_name: str
    raw_data: dict | None = None
    created_at: datetime
