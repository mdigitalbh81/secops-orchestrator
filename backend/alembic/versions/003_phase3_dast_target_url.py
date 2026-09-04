"""Phase 3 DAST target_url.

Revision ID: 003
Revises: 002
Create Date: 2026-09-03
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa

revision: str = "003"
down_revision: str | None = "002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("scans", sa.Column("target_url", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("scans", "target_url")
