from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import DateTime, Float, ForeignKey, String, Text
from sqlalchemy import Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.enums import EvidenceLevel, FindingStatus, Severity


class CorrelationGroup(Base):
    __tablename__ = "correlation_groups"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id"), nullable=False)
    canonical_title: Mapped[str] = mapped_column(String(500), nullable=False)
    canonical_cwe: Mapped[str | None] = mapped_column(String(50), nullable=True)
    canonical_cve: Mapped[str | None] = mapped_column(String(50), nullable=True)
    severity: Mapped[Severity] = mapped_column(SAEnum(Severity, native_enum=False), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    evidence_level: Mapped[EvidenceLevel] = mapped_column(
        SAEnum(EvidenceLevel, native_enum=False), default=EvidenceLevel.SINGLE_SOURCE
    )
    status: Mapped[FindingStatus] = mapped_column(
        SAEnum(FindingStatus, native_enum=False), default=FindingStatus.OPEN
    )
    remediation_recommendation: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )

    scan: Mapped[Scan] = relationship("Scan", back_populates="correlation_groups")
    findings: Mapped[list[Finding]] = relationship(
        "Finding", back_populates="correlation_group", lazy="selectin"
    )


from app.models.finding import Finding  # noqa: E402, F401
from app.models.scan import Scan  # noqa: E402, F401
