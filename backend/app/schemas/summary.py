from __future__ import annotations

from pydantic import BaseModel

from app.models.enums import RiskGate, ScanStatus


class SeverityTotals(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    unknown: int = 0


class ScanSummary(BaseModel):
    scan_id: str
    status: ScanStatus
    risk_gate: RiskGate | None = None
    totals: SeverityTotals
    scanner_runs: dict[str, str]
