from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.models.enums import ScannerRunStatus


class ScannerRunResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    scan_id: str
    scanner_name: str
    status: ScannerRunStatus
    error_message: str | None = None
    duration_seconds: float | None = None
    created_at: datetime
    completed_at: datetime | None = None
