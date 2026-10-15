# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Retained-source cleanup progress independent of publication update time.

Revision ID: 053_mobile_retention_cursor
Revises: 052_mobile_fact_epochs
"""

import sqlalchemy as sa

from alembic import op

revision = "053_mobile_retention_cursor"
down_revision = "052_mobile_fact_epochs"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("mobile_session_publications", sa.Column("last_checked_at", sa.DateTime(timezone=True)))
    op.create_index(
        "ix_mobile_publication_recheck",
        "mobile_session_publications",
        ["last_checked_at", "updated_at"],
        postgresql_where=sa.text("status IN ('complete','partial')"),
    )


def downgrade():
    op.drop_index("ix_mobile_publication_recheck", table_name="mobile_session_publications")
    op.drop_column("mobile_session_publications", "last_checked_at")
