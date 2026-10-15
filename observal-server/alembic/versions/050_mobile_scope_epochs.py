# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Subject/scope-local version counters for prospective paged mobile reads.

Revision ID: 050_mobile_scope_epochs
Revises: 049_mobile_read_barrier
"""

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

from alembic import op

revision = "050_mobile_scope_epochs"
down_revision = "049_mobile_read_barrier"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "mobile_scope_epochs",
        sa.Column("project_id", sa.String(64), primary_key=True),
        sa.Column("subject_id", UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("scope", sa.String(8), primary_key=True),
        sa.Column("epoch", sa.BigInteger(), nullable=False, server_default="0"),
        sa.CheckConstraint("scope IN ('author','user')", name="ck_mobile_scope_epoch_scope"),
    )
    op.create_index("ix_mobile_scope_epoch_subject", "mobile_scope_epochs", ["subject_id", "scope"])


def downgrade():
    op.drop_table("mobile_scope_epochs")
