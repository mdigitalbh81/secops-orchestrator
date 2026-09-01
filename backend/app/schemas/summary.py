from __future__ import annotations

from pydantic import BaseModel, Field

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
    correlated_totals: SeverityTotals = Field(default_factory=SeverityTotals)
    evidence_levels: dict[str, int] = Field(default_factory=dict)
    scanner_runs: dict[str, str]


class EvidenceSummary(BaseModel):
    scan_id: str
    total_findings: int = 0
    total_correlations: int = 0
    single_source_count: int = 0
    corroborated_static_count: int = 0
    runtime_validated_count: int = 0
    evidence_levels: dict[str, int] = Field(default_factory=dict)
