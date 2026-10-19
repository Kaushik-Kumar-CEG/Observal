# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Give an opened disposable cohort a database-clock deadline.

Revision ID: 065_mobile_synthetic_deadline
Revises: 064_mobile_revoke_guard
"""

import sqlalchemy as sa

from alembic import op

revision = "065_mobile_synthetic_deadline"
down_revision = "064_mobile_revoke_guard"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("mobile_read_controls", sa.Column("synthetic_expires_at", sa.DateTime(timezone=True)))


def downgrade():
    if op.get_bind().scalar(
        sa.text(
            "SELECT EXISTS (SELECT 1 FROM mobile_read_controls WHERE NOT blocked OR revocation_pending "
            "OR synthetic_expires_at IS NOT NULL)"
        )
    ):
        raise RuntimeError("Revoke and clear the armed synthetic cohort before removing its deadline")
    op.drop_column("mobile_read_controls", "synthetic_expires_at")
