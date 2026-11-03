# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Default-closed persistent availability and separately audited risk permission."""

import sqlalchemy as sa

from alembic import op

revision = "083_mobile_persistent_config"
down_revision = "082_mobile_synthetic_risk_audit"
branch_labels = None
depends_on = None

_BASE_ACTIONS = "'setup','open','revoking','revoke','follow_open','follow_close','follow_risk_open'"
_NEW_ACTIONS = "'follow_cfg_open','follow_cfg_close','follow_risk_arm'"


def upgrade():
    # No users, scopes, expiry, sources or existing audit records are changed.
    # Missing availability and seeding policy are explicitly default-OFF.
    op.execute(
        sa.text("""INSERT INTO enterprise_config(id,key,value,updated_at)
        VALUES (gen_random_uuid(),'mobile.follow_sync_v105_available','false',now()),
        (gen_random_uuid(),'mobile.follow_sync_v105_risk_permission','',now()),
        (gen_random_uuid(),'deployment.seed_demo_accounts','false',now())
        ON CONFLICT (key) DO NOTHING""")
    )
    op.drop_constraint("ck_mobile_operator_audit_action", "mobile_operator_audit", type_="check")
    op.create_check_constraint(
        "ck_mobile_operator_audit_action", "mobile_operator_audit", f"action IN ({_BASE_ACTIONS},{_NEW_ACTIONS})"
    )
    op.drop_constraint("ck_mobile_operator_audit_authority", "mobile_operator_audit", type_="check")
    op.create_check_constraint(
        "ck_mobile_operator_audit_authority",
        "mobile_operator_audit",
        "NOT (review_receipt_sha256 IS NOT NULL AND risk_acceptance_sha256 IS NOT NULL) AND "
        "(action NOT IN ('follow_risk_open','follow_risk_arm') OR "
        "(risk_acceptance_sha256 IS NOT NULL AND review_receipt_sha256 IS NULL))",
    )


def downgrade():
    if op.get_bind().scalar(
        sa.text(f"SELECT EXISTS (SELECT 1 FROM mobile_operator_audit WHERE action IN ({_NEW_ACTIONS}))")
    ):
        raise RuntimeError("Refusing to discard persistent configuration audit; retain schema and deny authority")
    op.drop_constraint("ck_mobile_operator_audit_authority", "mobile_operator_audit", type_="check")
    op.create_check_constraint(
        "ck_mobile_operator_audit_authority",
        "mobile_operator_audit",
        "NOT (review_receipt_sha256 IS NOT NULL AND risk_acceptance_sha256 IS NOT NULL) AND "
        "(action <> 'follow_risk_open' OR (risk_acceptance_sha256 IS NOT NULL AND review_receipt_sha256 IS NULL))",
    )
    op.drop_constraint("ck_mobile_operator_audit_action", "mobile_operator_audit", type_="check")
    op.create_check_constraint(
        "ck_mobile_operator_audit_action", "mobile_operator_audit", f"action IN ({_BASE_ACTIONS})"
    )
    # Keep durable settings even on an unexercised downgrade; never turn an
    # absent environment flag into authority or resurrect automatic seeding.
