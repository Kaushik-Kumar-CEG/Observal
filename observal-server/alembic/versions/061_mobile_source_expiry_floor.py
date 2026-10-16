# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Fail closed typed reads before any verified Pi source row reaches raw-line TTL.

Revision ID: 061_mobile_source_expiry_floor
Revises: 060_mobile_pi_hook_facts
"""

import sqlalchemy as sa

from alembic import op

revision = "061_mobile_source_expiry_floor"
down_revision = "060_mobile_pi_hook_facts"
branch_labels = None
depends_on = None


def upgrade():
    # Existing publications remain unavailable until the worker has re-read
    # their complete retained source. Never invent an expiry from updated_at.
    op.add_column("mobile_session_publications", sa.Column("source_retained_until", sa.DateTime(timezone=True)))


def downgrade():
    op.drop_column("mobile_session_publications", "source_retained_until")
