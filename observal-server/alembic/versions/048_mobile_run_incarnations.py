# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Quarantine scoped Pi session-ID reuse and persist prospective run identity.

Revision ID: 048_mobile_run_incarnations
Revises: 047_mobile_retained_prefix
"""

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

from alembic import op

revision = "048_mobile_run_incarnations"
down_revision = "047_mobile_retained_prefix"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "mobile_run_instances",
        sa.Column("project_id", sa.String(64), primary_key=True),
        sa.Column("user_id", UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("harness", sa.String(32), primary_key=True),
        sa.Column("session_id", sa.String(256), primary_key=True),
        sa.Column("run_incarnation", UUID(as_uuid=True), nullable=False),
        sa.Column("header_hash", sa.String(64), nullable=False),
        sa.Column("parent_run_incarnation", UUID(as_uuid=True), nullable=True),
        # Neither a missing parent nor a Pi source header attests an interactive
        # root. Only a separate verified launcher/lineage authority may set it.
        sa.Column("root_verified", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("source_status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("project_id", "user_id", "harness", "run_incarnation", name="uq_mobile_run_incarnation"),
    )
    op.create_index(
        "ix_mobile_run_parent", "mobile_run_instances", ["project_id", "user_id", "harness", "parent_run_incarnation"]
    )
    op.create_index(
        "ix_mobile_run_coverage", "mobile_run_instances", ["project_id", "user_id", "harness", "source_status"]
    )
    op.add_column("mobile_evidence_events", sa.Column("run_incarnation", UUID(as_uuid=True), nullable=True))
    op.add_column("mobile_evidence_events", sa.Column("root_run_incarnation", UUID(as_uuid=True), nullable=True))
    op.create_index(
        "ix_mobile_evidence_actor_root",
        "mobile_evidence_events",
        ["project_id", "user_id", "event_time", "root_run_incarnation"],
    )
    op.create_index(
        "ix_mobile_evidence_listing_root",
        "mobile_evidence_events",
        ["project_id", "component_id", "event_time", "user_id", "root_run_incarnation"],
    )


def downgrade():
    op.drop_index("ix_mobile_evidence_listing_root", table_name="mobile_evidence_events")
    op.drop_index("ix_mobile_evidence_actor_root", table_name="mobile_evidence_events")
    op.drop_column("mobile_evidence_events", "root_run_incarnation")
    op.drop_column("mobile_evidence_events", "run_incarnation")
    op.drop_table("mobile_run_instances")
