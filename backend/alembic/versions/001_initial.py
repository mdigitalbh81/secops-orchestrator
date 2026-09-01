"""Initial schema.

Revision ID: 001
Revises:
Create Date: 2024-01-01
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "projects",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("repository_url", sa.Text, nullable=True),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "scans",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("project_id", sa.String(36), sa.ForeignKey("projects.id"), nullable=False),
        sa.Column("source_path", sa.Text, nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="PENDING"),
        sa.Column("risk_gate", sa.String(20), nullable=True),
        sa.Column("error_message", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_table(
        "scanner_runs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("scan_id", sa.String(36), sa.ForeignKey("scans.id"), nullable=False),
        sa.Column("scanner_name", sa.String(100), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("error_message", sa.Text, nullable=True),
        sa.Column("duration_seconds", sa.Float, nullable=True),
        sa.Column("raw_output", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_table(
        "findings",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("scan_id", sa.String(36), sa.ForeignKey("scans.id"), nullable=False),
        sa.Column("scanner_name", sa.String(100), nullable=False),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("confidence", sa.Float, nullable=False),
        sa.Column("cwe", sa.String(50), nullable=True),
        sa.Column("cve", sa.String(50), nullable=True),
        sa.Column("file_path", sa.Text, nullable=True),
        sa.Column("line_start", sa.Integer, nullable=True),
        sa.Column("line_end", sa.Integer, nullable=True),
        sa.Column("package_name", sa.String(255), nullable=True),
        sa.Column("installed_version", sa.String(100), nullable=True),
        sa.Column("fixed_version", sa.String(100), nullable=True),
        sa.Column("url", sa.Text, nullable=True),
        sa.Column("raw_fingerprint", sa.String(255), nullable=False),
        sa.Column("normalized_fingerprint", sa.String(255), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="OPEN"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "finding_evidences",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("finding_id", sa.String(36), sa.ForeignKey("findings.id"), nullable=False),
        sa.Column("scanner_name", sa.String(100), nullable=False),
        sa.Column("raw_data", sa.JSON, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("finding_evidences")
    op.drop_table("findings")
    op.drop_table("scanner_runs")
    op.drop_table("scans")
    op.drop_table("projects")
