from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import DateTime, Float, ForeignKey, String, Text
from sqlalchemy import Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.enums import ScannerRunStatus


class ScannerRun(Base):
    __tablename__ = "scanner_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id"), nullable=False)
    scanner_name: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[ScannerRunStatus] = mapped_column(
        SAEnum(ScannerRunStatus, native_enum=False), default=ScannerRunStatus.APPLICABLE
    )
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    duration_seconds: Mapped[float | None] = mapped_column(Float, nullable=True)
    raw_output: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    scan: Mapped[Scan] = relationship("Scan", back_populates="scanner_runs")


from app.models.scan import Scan  # noqa: E402, F401
