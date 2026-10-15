# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Prospective source-verified zero-positive Pi MCP candidate activity.

Revision ID: 055_mobile_zero_cohort
Revises: 054_mobile_pi_origin
"""

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

from alembic import op

revision = "055_mobile_zero_cohort"
down_revision = "054_mobile_pi_origin"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "mobile_eligible_event_times",
        sa.Column("project_id", sa.String(64), primary_key=True),
        sa.Column("user_id", UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("harness", sa.String(32), primary_key=True),
        sa.Column("session_id", sa.String(256), primary_key=True),
        sa.Column("source_line_offset", sa.Integer, primary_key=True),
        sa.Column("root_run_incarnation", UUID(as_uuid=True), nullable=False),
        sa.Column("layer_hash", sa.String(67), nullable=False),
        sa.ForeignKeyConstraint(
            ["project_id", "user_id", "harness", "layer_hash"],
            [
                "mobile_verified_layers.project_id",
                "mobile_verified_layers.user_id",
                "mobile_verified_layers.harness",
                "mobile_verified_layers.layer_hash",
            ],
            ondelete="CASCADE",
        ),
        sa.Column("source_revision", sa.String(64), nullable=False),
        sa.Column("event_time", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_mobile_eligible_actor_time", "mobile_eligible_event_times", ["project_id", "user_id", "event_time"]
    )


def downgrade():
    op.drop_index("ix_mobile_eligible_actor_time", table_name="mobile_eligible_event_times")
    op.drop_table("mobile_eligible_event_times")
