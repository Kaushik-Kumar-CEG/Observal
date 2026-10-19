# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Keep emergency deny durable even when setting/audit writes fail.

Revision ID: 064_mobile_revoke_guard
Revises: 063_first_admin_provision_audit
"""

import sqlalchemy as sa

from alembic import op

revision = "064_mobile_revoke_guard"
down_revision = "063_first_admin_provision_audit"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "mobile_read_controls", sa.Column("revocation_pending", sa.Boolean(), nullable=False, server_default=sa.false())
    )
    op.add_column("mobile_read_controls", sa.Column("revocation_actor_id", sa.Uuid(), nullable=True))
    op.add_column("mobile_read_controls", sa.Column("revocation_started_at", sa.DateTime(timezone=True), nullable=True))


def downgrade():
    if op.get_bind().scalar(sa.text("SELECT EXISTS (SELECT 1 FROM mobile_read_controls WHERE revocation_pending)")):
        raise RuntimeError("Refusing to remove an unfinished mobile revoke; keep the read barrier closed")
    op.drop_column("mobile_read_controls", "revocation_started_at")
    op.drop_column("mobile_read_controls", "revocation_actor_id")
    op.drop_column("mobile_read_controls", "revocation_pending")
