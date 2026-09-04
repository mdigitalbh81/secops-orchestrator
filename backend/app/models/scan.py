from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy import Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.enums import RiskGate, ScanStatus


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    project_id: Mapped[str] = mapped_column(String(36), ForeignKey("projects.id"), nullable=False)
    source_path: Mapped[str] = mapped_column(Text, nullable=False)
    target_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[ScanStatus] = mapped_column(
        SAEnum(ScanStatus, native_enum=False), default=ScanStatus.PENDING
    )
    risk_gate: Mapped[RiskGate | None] = mapped_column(
        SAEnum(RiskGate, native_enum=False), nullable=True
    )
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    project: Mapped[Project] = relationship("Project", back_populates="scans")
    scanner_runs: Mapped[list[ScannerRun]] = relationship(
        "ScannerRun", back_populates="scan", lazy="selectin"
    )
    findings: Mapped[list[Finding]] = relationship(
        "Finding", back_populates="scan", lazy="selectin"
    )
    correlation_groups: Mapped[list[CorrelationGroup]] = relationship(
        "CorrelationGroup", back_populates="scan", lazy="selectin"
    )


from app.models.correlation import CorrelationGroup  # noqa: E402, F401
from app.models.finding import Finding  # noqa: E402, F401
from app.models.project import Project  # noqa: E402, F401
from app.models.scanner_run import ScannerRun  # noqa: E402, F401
