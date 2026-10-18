# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Durable receipt for the operator's local, one-shot first super-admin.

Revision ID: 063_first_admin_provision_audit
Revises: 062_mobile_operator_audit
"""

import sqlalchemy as sa

from alembic import op

revision = "063_first_admin_provision_audit"
down_revision = "062_mobile_operator_audit"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "first_admin_provision_audit",
        sa.Column("id", sa.Uuid(), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("actor_id", sa.Uuid(), nullable=False),
        sa.Column("action", sa.String(40), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("action='local_first_super_admin'", name="ck_first_admin_provision_action"),
    )


def downgrade():
    if op.get_bind().scalar(sa.text("SELECT EXISTS (SELECT 1 FROM first_admin_provision_audit)")):
        raise RuntimeError("Refusing to discard first-admin provisioning receipts; restore a pre-063 isolated backup")
    op.drop_table("first_admin_provision_audit")
