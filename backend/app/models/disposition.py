"""Finding disposition and audit trail models."""
from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import DateTime, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy import Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.models.enums import FindingStatus


class FindingDisposition(Base):
    __tablename__ = "finding_dispositions"
    __table_args__ = (
        UniqueConstraint(
            "project_id", "scanner_name", "normalized_fingerprint",
            name="uq_disposition_identity",
        ),
    )

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    project_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("projects.id"), nullable=False
    )
    scanner_name: Mapped[str] = mapped_column(String(100), nullable=False)
    normalized_fingerprint: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[FindingStatus] = mapped_column(
        SAEnum(FindingStatus, native_enum=False), nullable=False
    )
    justification: Mapped[str] = mapped_column(Text, nullable=False)
    actor: Mapped[str] = mapped_column(String(255), nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    source_finding_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("findings.id"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )


class FindingDispositionEvent(Base):
    __tablename__ = "finding_disposition_events"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    project_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("projects.id"), nullable=False
    )
    scan_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("scans.id"), nullable=True
    )
    finding_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("findings.id"), nullable=True
    )
    scanner_name: Mapped[str] = mapped_column(String(100), nullable=False)
    normalized_fingerprint: Mapped[str] = mapped_column(String(255), nullable=False)
    previous_status: Mapped[FindingStatus] = mapped_column(
        SAEnum(FindingStatus, native_enum=False), nullable=False
    )
    new_status: Mapped[FindingStatus] = mapped_column(
        SAEnum(FindingStatus, native_enum=False), nullable=False
    )
    justification: Mapped[str] = mapped_column(Text, nullable=False)
    actor: Mapped[str] = mapped_column(String(255), nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )
