# SPDX-FileCopyrightText: 2026 Kaushik Kumar <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0

"""Add success_criteria to agent_versions.

Revision ID: 021_agent_success_criteria
Revises: 020_remove_legacy_scope
"""

import sqlalchemy as sa

from alembic import op

revision = "021_agent_success_criteria"
down_revision = "020_remove_legacy_scope"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("agent_versions", sa.Column("success_criteria", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("agent_versions", "success_criteria")
