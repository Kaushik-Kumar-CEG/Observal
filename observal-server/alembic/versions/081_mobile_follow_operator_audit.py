# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Distinguish reviewed synthetic Following switches in the durable operator trail.

Revision ID: 081_mobile_follow_operator_audit
Revises: 080_mobile_follow_browser_proof
"""

import sqlalchemy as sa

from alembic import op

revision = "081_mobile_follow_operator_audit"
down_revision = "080_mobile_follow_browser_proof"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("mobile_operator_audit", sa.Column("review_receipt_sha256", sa.String(64), nullable=True))
    op.drop_constraint("ck_mobile_operator_audit_action", "mobile_operator_audit", type_="check")
    op.create_check_constraint(
        "ck_mobile_operator_audit_action",
        "mobile_operator_audit",
        "action IN ('setup','open','revoking','revoke','follow_open','follow_close')",
    )


def downgrade():
    if op.get_bind().scalar(
        sa.text("SELECT EXISTS (SELECT 1 FROM mobile_operator_audit WHERE action IN ('follow_open','follow_close'))")
    ):
        raise RuntimeError("Refusing to discard Following operator audit history; use an approved backup/restore plan")
    op.drop_constraint("ck_mobile_operator_audit_action", "mobile_operator_audit", type_="check")
    op.create_check_constraint(
        "ck_mobile_operator_audit_action", "mobile_operator_audit", "action IN ('setup','open','revoking','revoke')"
    )
    op.drop_column("mobile_operator_audit", "review_receipt_sha256")
