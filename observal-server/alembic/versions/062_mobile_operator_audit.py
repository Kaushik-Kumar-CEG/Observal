# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Commit mobile test gate transitions and an operator record in the same transaction.

Revision ID: 062_mobile_operator_audit
Revises: 061_mobile_source_expiry_floor
"""

import sqlalchemy as sa

from alembic import op

revision = "062_mobile_operator_audit"
down_revision = "061_mobile_source_expiry_floor"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "mobile_operator_audit",
        sa.Column("id", sa.Uuid(), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("project_id", sa.String(255), nullable=False),
        sa.Column("actor_id", sa.Uuid(), nullable=False),
        sa.Column("action", sa.String(16), nullable=False),
        sa.Column("generation", sa.BigInteger(), nullable=False),
        sa.Column("server_id", sa.Uuid()),
        sa.Column("author_viewer_id", sa.Uuid()),
        sa.Column("user_viewer_id", sa.Uuid()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("action IN ('setup','open','revoking','revoke')", name="ck_mobile_operator_audit_action"),
    )


def downgrade():
    op.drop_table("mobile_operator_audit")
