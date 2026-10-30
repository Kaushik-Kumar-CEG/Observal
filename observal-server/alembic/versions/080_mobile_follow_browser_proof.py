# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Distinguish normal browser-approved challenges from legacy synthetic approvals.

Revision ID: 080_mobile_follow_browser_proof
Revises: 079_mobile_follow_sync_state
"""

from alembic import op

revision = "080_mobile_follow_browser_proof"
down_revision = "079_mobile_follow_sync_state"
branch_labels = None
depends_on = None


def upgrade():
    op.execute("ALTER TABLE mobile_follow_approvals ADD COLUMN browser_action_proven boolean NOT NULL DEFAULT false")


def downgrade():
    op.execute("ALTER TABLE mobile_follow_approvals DROP COLUMN browser_action_proven")
