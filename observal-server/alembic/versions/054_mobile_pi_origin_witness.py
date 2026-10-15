# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Persist prospective Pi lifecycle witness separately from client source shape.

Revision ID: 054_mobile_pi_origin
Revises: 053_mobile_retention_cursor
"""

import sqlalchemy as sa

from alembic import op

revision = "054_mobile_pi_origin"
down_revision = "053_mobile_retention_cursor"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("mobile_run_instances", sa.Column("origin_witness", sa.String(32)))
    op.create_check_constraint(
        "ck_mobile_pi_origin_witness",
        "mobile_run_instances",
        "origin_witness IS NULL OR origin_witness='pi_session_start_root_v1'",
    )


def downgrade():
    op.drop_constraint("ck_mobile_pi_origin_witness", "mobile_run_instances", type_="check")
    op.drop_column("mobile_run_instances", "origin_witness")
