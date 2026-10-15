# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Bind prospective Pi child sessions to one same-actor parent incarnation.

Revision ID: 057_mobile_pi_parent
Revises: 056_mobile_zero_epochs
"""

import sqlalchemy as sa

from alembic import op

revision = "057_mobile_pi_parent"
down_revision = "056_mobile_zero_epochs"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("mobile_run_instances", sa.Column("parent_session_id", sa.String(256), nullable=True))
    op.add_column("mobile_run_instances", sa.Column("parent_header_hash", sa.String(64), nullable=True))
    op.add_column("mobile_run_instances", sa.Column("started_at", sa.DateTime(timezone=True), nullable=True))
    op.create_check_constraint(
        "ck_mobile_pi_parent_complete",
        "mobile_run_instances",
        "(parent_session_id IS NULL AND parent_run_incarnation IS NULL AND parent_header_hash IS NULL) "
        "OR (parent_session_id IS NOT NULL AND parent_run_incarnation IS NOT NULL AND parent_header_hash IS NOT NULL)",
    )


def downgrade():
    op.drop_constraint("ck_mobile_pi_parent_complete", "mobile_run_instances", type_="check")
    op.drop_column("mobile_run_instances", "started_at")
    op.drop_column("mobile_run_instances", "parent_header_hash")
    op.drop_column("mobile_run_instances", "parent_session_id")
