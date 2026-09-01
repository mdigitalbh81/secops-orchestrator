from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import JSON, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy import Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.enums import FindingStatus, Severity


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id"), nullable=False)
    scanner_name: Mapped[str] = mapped_column(String(100), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[Severity] = mapped_column(
        SAEnum(Severity, native_enum=False), default=Severity.UNKNOWN
    )
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    cwe: Mapped[str | None] = mapped_column(String(50), nullable=True)
    cve: Mapped[str | None] = mapped_column(String(50), nullable=True)
    file_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    line_start: Mapped[int | None] = mapped_column(Integer, nullable=True)
    line_end: Mapped[int | None] = mapped_column(Integer, nullable=True)
    package_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    installed_version: Mapped[str | None] = mapped_column(String(100), nullable=True)
    fixed_version: Mapped[str | None] = mapped_column(String(100), nullable=True)
    url: Mapped[str | None] = mapped_column(Text, nullable=True)
    raw_fingerprint: Mapped[str] = mapped_column(String(255), nullable=False)
    normalized_fingerprint: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[FindingStatus] = mapped_column(
        SAEnum(FindingStatus, native_enum=False), default=FindingStatus.OPEN
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )

    scan: Mapped[Scan] = relationship("Scan", back_populates="findings")
    evidences: Mapped[list[FindingEvidence]] = relationship(
        "FindingEvidence", back_populates="finding", lazy="selectin"
    )


class FindingEvidence(Base):
    __tablename__ = "finding_evidences"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    finding_id: Mapped[str] = mapped_column(String(36), ForeignKey("findings.id"), nullable=False)
    scanner_name: Mapped[str] = mapped_column(String(100), nullable=False)
    raw_data: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )

    finding: Mapped[Finding] = relationship("Finding", back_populates="evidences")


from app.models.scan import Scan  # noqa: E402, F401
