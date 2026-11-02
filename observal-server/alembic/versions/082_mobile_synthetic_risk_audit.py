# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Keep synthetic owner risk acceptance distinct from independent review."""

import sqlalchemy as sa

from alembic import op

revision = "082_mobile_synthetic_risk_audit"
down_revision = "081_mobile_follow_operator_audit"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("mobile_operator_audit", sa.Column("risk_acceptance_sha256", sa.String(64), nullable=True))
    op.drop_constraint("ck_mobile_operator_audit_action", "mobile_operator_audit", type_="check")
    op.create_check_constraint(
        "ck_mobile_operator_audit_action",
        "mobile_operator_audit",
        "action IN ('setup','open','revoking','revoke','follow_open','follow_close','follow_risk_open')",
    )
    op.create_check_constraint(
        "ck_mobile_operator_audit_authority",
        "mobile_operator_audit",
        "NOT (review_receipt_sha256 IS NOT NULL AND risk_acceptance_sha256 IS NOT NULL) AND "
        "(action <> 'follow_risk_open' OR (risk_acceptance_sha256 IS NOT NULL AND review_receipt_sha256 IS NULL))",
    )


def downgrade():
    if op.get_bind().scalar(
        sa.text("SELECT EXISTS (SELECT 1 FROM mobile_operator_audit WHERE risk_acceptance_sha256 IS NOT NULL)")
    ):
        raise RuntimeError("Refusing to discard owner risk acceptance history; retain schema and deny authority")
    op.drop_constraint("ck_mobile_operator_audit_authority", "mobile_operator_audit", type_="check")
    op.drop_constraint("ck_mobile_operator_audit_action", "mobile_operator_audit", type_="check")
    op.create_check_constraint(
        "ck_mobile_operator_audit_action",
        "mobile_operator_audit",
        "action IN ('setup','open','revoking','revoke','follow_open','follow_close')",
    )
    op.drop_column("mobile_operator_audit", "risk_acceptance_sha256")
