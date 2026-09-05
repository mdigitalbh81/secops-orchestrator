"""Finding dispositions and audit trail.

Revision ID: 004
Revises: 003
Create Date: 2026-09-04
"""
from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa

revision: str = "004"
down_revision: str | None = "003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "finding_dispositions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "project_id",
            sa.String(36),
            sa.ForeignKey("projects.id"),
            nullable=False,
        ),
        sa.Column("scanner_name", sa.String(100), nullable=False),
        sa.Column("normalized_fingerprint", sa.String(255), nullable=False),
        sa.Column("status", sa.String(50), nullable=False),
        sa.Column("justification", sa.Text(), nullable=False),
        sa.Column("actor", sa.String(255), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "source_finding_id",
            sa.String(36),
            sa.ForeignKey("findings.id"),
            nullable=True,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.UniqueConstraint(
            "project_id",
            "scanner_name",
            "normalized_fingerprint",
            name="uq_disposition_identity",
        ),
    )
    op.create_index(
        "ix_disposition_project_scanner_fp",
        "finding_dispositions",
        ["project_id", "scanner_name", "normalized_fingerprint"],
    )

    op.create_table(
        "finding_disposition_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "project_id",
            sa.String(36),
            sa.ForeignKey("projects.id"),
            nullable=False,
        ),
        sa.Column(
            "scan_id",
            sa.String(36),
            sa.ForeignKey("scans.id"),
            nullable=True,
        ),
        sa.Column(
            "finding_id",
            sa.String(36),
            sa.ForeignKey("findings.id"),
            nullable=True,
        ),
        sa.Column("scanner_name", sa.String(100), nullable=False),
        sa.Column("normalized_fingerprint", sa.String(255), nullable=False),
        sa.Column("previous_status", sa.String(50), nullable=False),
        sa.Column("new_status", sa.String(50), nullable=False),
        sa.Column("justification", sa.Text(), nullable=False),
        sa.Column("actor", sa.String(255), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index(
        "ix_event_finding_id",
        "finding_disposition_events",
        ["finding_id"],
    )
    op.create_index(
        "ix_event_project_scanner_fp",
        "finding_disposition_events",
        ["project_id", "scanner_name", "normalized_fingerprint"],
    )


def downgrade() -> None:
    op.drop_index("ix_event_project_scanner_fp", table_name="finding_disposition_events")
    op.drop_index("ix_event_finding_id", table_name="finding_disposition_events")
    op.drop_table("finding_disposition_events")
    op.drop_index("ix_disposition_project_scanner_fp", table_name="finding_dispositions")
    op.drop_table("finding_dispositions")
