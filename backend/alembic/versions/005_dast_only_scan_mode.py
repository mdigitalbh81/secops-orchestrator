"""DAST-only scan mode: add scan_mode column, make source_path nullable.

Revision ID: 005
Revises: 004
Create Date: 2026-09-06
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa

revision: str = "005"
down_revision: str | None = "004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Add scan_mode column with default SOURCE for existing rows
    op.add_column(
        "scans",
        sa.Column("scan_mode", sa.String(20), nullable=False, server_default="SOURCE"),
    )
    # Make source_path nullable for DAST-only scans
    op.alter_column("scans", "source_path", existing_type=sa.Text(), nullable=True)


def downgrade() -> None:
    # Before enforcing NOT NULL on source_path, assign a clearly identifiable
    # legacy non-null path to any DAST-only scans that have source_path = NULL.
    # This preserves historical scan records without deleting rows, while satisfying
    # the schema 004 NOT NULL constraint during structural downgrade.
    # Legacy path format: /tmp/secops-workspaces/dast-only-downgraded/<scan_id>
    conn = op.get_bind()
    conn.execute(
        sa.text(
            "UPDATE scans "
            "SET source_path = '/tmp/secops-workspaces/dast-only-downgraded/' || id "
            "WHERE source_path IS NULL"
        )
    )
    op.alter_column("scans", "source_path", existing_type=sa.Text(), nullable=False)
    op.drop_column("scans", "scan_mode")
