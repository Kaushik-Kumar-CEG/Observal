# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Fail-closed project-wide mobile read control before asynchronous source purge.

Revision ID: 049_mobile_read_barrier
Revises: 048_mobile_run_incarnations
"""

import sqlalchemy as sa

from alembic import op

revision = "049_mobile_read_barrier"
down_revision = "048_mobile_run_incarnations"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "mobile_read_controls",
        sa.Column("project_id", sa.String(64), primary_key=True),
        sa.Column("blocked", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("generation", sa.BigInteger(), nullable=False, server_default="1"),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    # No completion/coverage proof exists yet. A newly installed project is
    # deliberately unavailable until a separate reviewed qualification gate.
    op.execute("INSERT INTO mobile_read_controls(project_id,blocked) VALUES ('default',true)")


def downgrade():
    op.drop_table("mobile_read_controls")
