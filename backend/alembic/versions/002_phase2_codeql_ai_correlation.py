"""Phase 2 CodeQL AI Correlation and Evidence Level.

Revision ID: 002
Revises: 001
Create Date: 2026-09-01
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa

revision: str = "002"
down_revision: str | None = "001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "correlation_groups",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("scan_id", sa.String(36), sa.ForeignKey("scans.id"), nullable=False),
        sa.Column("canonical_title", sa.String(500), nullable=False),
        sa.Column("canonical_cwe", sa.String(50), nullable=True),
        sa.Column("canonical_cve", sa.String(50), nullable=True),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("confidence", sa.Float, nullable=False),
        sa.Column("evidence_level", sa.String(50), nullable=False, server_default="SINGLE_SOURCE"),
        sa.Column("status", sa.String(20), nullable=False, server_default="OPEN"),
        sa.Column("remediation_recommendation", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.add_column(
        "findings",
        sa.Column(
            "evidence_level",
            sa.String(50),
            nullable=False,
            server_default="SINGLE_SOURCE",
        ),
    )
    op.add_column(
        "findings",
        sa.Column(
            "correlation_group_id",
            sa.String(36),
            sa.ForeignKey("correlation_groups.id"),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column("findings", "correlation_group_id")
    op.drop_column("findings", "evidence_level")
    op.drop_table("correlation_groups")
