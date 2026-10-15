# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Bounded retained-source reconciliation cursor.

Revision ID: 046_mobile_backfill_cursor
Revises: 045_mobile_provenance
"""

import sqlalchemy as sa

from alembic import op

revision = "046_mobile_backfill_cursor"
down_revision = "045_mobile_provenance"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "mobile_backfill_cursor",
        sa.Column("singleton", sa.Boolean(), primary_key=True),
        sa.Column("project_id", sa.String(64), nullable=False, server_default=""),
        sa.Column("user_id", sa.String(64), nullable=False, server_default=""),
        sa.Column("session_id", sa.String(256), nullable=False, server_default=""),
        sa.CheckConstraint("singleton", name="ck_mobile_backfill_cursor_singleton"),
    )
    op.execute("INSERT INTO mobile_backfill_cursor(singleton) VALUES (true)")


def downgrade():
    op.drop_table("mobile_backfill_cursor")
