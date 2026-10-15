# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Record when a retained source is a contiguous suffix, not a full session.

Revision ID: 047_mobile_retained_prefix
Revises: 046_mobile_backfill_cursor
"""

import sqlalchemy as sa

from alembic import op

revision = "047_mobile_retained_prefix"
down_revision = "046_mobile_backfill_cursor"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "mobile_session_publications",
        sa.Column("first_source_offset", sa.Integer(), nullable=False, server_default="0"),
    )
    op.create_check_constraint(
        "ck_mobile_publication_source_offset", "mobile_session_publications", "first_source_offset >= 0"
    )


def downgrade():
    op.drop_constraint("ck_mobile_publication_source_offset", "mobile_session_publications", type_="check")
    op.drop_column("mobile_session_publications", "first_source_offset")
