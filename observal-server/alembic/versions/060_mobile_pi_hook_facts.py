# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Result-checked Pi hook receipts bound to original approved command versions.

Revision ID: 060_mobile_pi_hook_facts
Revises: 059_mobile_pi_skill_facts
"""

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

from alembic import op

revision = "060_mobile_pi_hook_facts"
down_revision = "059_mobile_pi_skill_facts"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "mobile_verified_layers",
        sa.Column("expected_hooks", sa.SmallInteger(), nullable=False, server_default="0"),
    )
    op.create_table(
        "mobile_hook_layer_components",
        sa.Column("project_id", sa.String(64), primary_key=True),
        sa.Column("user_id", UUID(as_uuid=True), primary_key=True),
        sa.Column("harness", sa.String(32), primary_key=True),
        sa.Column("layer_hash", sa.String(67), primary_key=True),
        sa.Column("binding_sha256", sa.String(64), primary_key=True),
        sa.Column("event", sa.String(16), nullable=False),
        sa.CheckConstraint("event IN ('tool_call','tool_result')", name="ck_mobile_hook_binding_event"),
        sa.Column("alias", sa.String(128), nullable=False),
        sa.Column(
            "component_id", UUID(as_uuid=True), sa.ForeignKey("hook_listings.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column(
            "version_id", UUID(as_uuid=True), sa.ForeignKey("hook_versions.id", ondelete="CASCADE"), nullable=False
        ),
        sa.UniqueConstraint(
            "project_id",
            "user_id",
            "harness",
            "layer_hash",
            "binding_sha256",
            "component_id",
            name="uq_mobile_hook_binding_component",
        ),
        sa.ForeignKeyConstraint(
            ["project_id", "user_id", "harness", "layer_hash"],
            [
                "mobile_verified_layers.project_id",
                "mobile_verified_layers.user_id",
                "mobile_verified_layers.harness",
                "mobile_verified_layers.layer_hash",
            ],
            ondelete="CASCADE",
        ),
    )
    op.create_table(
        "mobile_hook_evidence_events",
        sa.Column("project_id", sa.String(64), primary_key=True),
        sa.Column("user_id", UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("harness", sa.String(32), primary_key=True),
        sa.Column("session_id", sa.String(256), primary_key=True),
        sa.Column("source_line_offset", sa.Integer(), primary_key=True),
        sa.Column("block_key", sa.String(270), primary_key=True),
        sa.Column("layer_hash", sa.String(67), nullable=False),
        sa.Column("binding_sha256", sa.String(64), nullable=False),
        sa.Column(
            "component_id", UUID(as_uuid=True), sa.ForeignKey("hook_listings.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("source_revision", sa.String(64), nullable=False),
        sa.Column("run_incarnation", UUID(as_uuid=True), nullable=False),
        sa.Column("root_session_id", sa.String(256), nullable=False),
        sa.Column("root_run_incarnation", UUID(as_uuid=True), nullable=False),
        sa.Column("event_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("outcome", sa.String(16), nullable=False),
        sa.CheckConstraint(
            "outcome IN ('ran','ran_with_output','failed','blocked')", name="ck_mobile_hook_receipt_outcome"
        ),
        sa.ForeignKeyConstraint(
            ["project_id", "user_id", "harness", "layer_hash", "binding_sha256", "component_id"],
            [
                "mobile_hook_layer_components.project_id",
                "mobile_hook_layer_components.user_id",
                "mobile_hook_layer_components.harness",
                "mobile_hook_layer_components.layer_hash",
                "mobile_hook_layer_components.binding_sha256",
                "mobile_hook_layer_components.component_id",
            ],
            ondelete="CASCADE",
        ),
    )
    op.create_index("ix_mobile_hook_actor_time", "mobile_hook_evidence_events", ["user_id", "event_time"])
    op.create_index("ix_mobile_hook_component_time", "mobile_hook_evidence_events", ["component_id", "event_time"])
    op.execute("""
        CREATE FUNCTION mobile_bump_hook_scope_epochs() RETURNS trigger LANGUAGE plpgsql AS $$
        DECLARE target uuid;
        BEGIN
            IF TG_TABLE_NAME='hook_listings' THEN
                target := CASE WHEN TG_OP='DELETE' THEN OLD.id ELSE NEW.id END;
            ELSE
                target := NEW.listing_id;
            END IF;
            INSERT INTO mobile_scope_epochs(project_id,subject_id,scope,epoch)
            SELECT DISTINCT project_id,user_id,'user',1 FROM mobile_hook_evidence_events WHERE component_id=target
            ON CONFLICT (project_id,subject_id,scope) DO UPDATE SET epoch=mobile_scope_epochs.epoch+1;
            INSERT INTO mobile_scope_epochs(project_id,subject_id,scope,epoch)
            SELECT DISTINCT e.project_id,p.original_author_id,'author',1 FROM mobile_hook_evidence_events e
            JOIN mobile_listing_provenance p ON p.kind='hook' AND p.listing_id=e.component_id
            WHERE e.component_id=target
            ON CONFLICT (project_id,subject_id,scope) DO UPDATE SET epoch=mobile_scope_epochs.epoch+1;
            IF TG_OP='DELETE' THEN RETURN OLD; END IF;
            RETURN NEW;
        END $$
    """)
    op.execute(
        "CREATE TRIGGER mobile_hook_delete_epoch BEFORE DELETE ON hook_listings FOR EACH ROW EXECUTE FUNCTION mobile_bump_hook_scope_epochs()"
    )
    op.execute(
        "CREATE TRIGGER mobile_hook_visibility_epoch AFTER UPDATE OF is_private ON hook_listings FOR EACH ROW WHEN (OLD.is_private IS DISTINCT FROM NEW.is_private) EXECUTE FUNCTION mobile_bump_hook_scope_epochs()"
    )
    op.execute(
        "CREATE TRIGGER mobile_hook_review_epoch AFTER UPDATE OF status ON hook_versions FOR EACH ROW WHEN (OLD.status IS DISTINCT FROM NEW.status) EXECUTE FUNCTION mobile_bump_hook_scope_epochs()"
    )
    for action, relation in (("insert", "new_events"), ("delete", "old_events")):
        op.execute(f"""
            CREATE FUNCTION mobile_hook_fact_epoch_{action}() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
                INSERT INTO mobile_scope_epochs(project_id,subject_id,scope,epoch)
                SELECT DISTINCT project_id,user_id,'user',1 FROM {relation}
                ON CONFLICT (project_id,subject_id,scope) DO UPDATE SET epoch=mobile_scope_epochs.epoch+1;
                INSERT INTO mobile_scope_epochs(project_id,subject_id,scope,epoch)
                SELECT DISTINCT e.project_id,p.original_author_id,'author',1 FROM {relation} e
                JOIN mobile_listing_provenance p ON p.kind='hook' AND p.listing_id=e.component_id
                JOIN users u ON u.id=p.original_author_id
                ON CONFLICT (project_id,subject_id,scope) DO UPDATE SET epoch=mobile_scope_epochs.epoch+1;
                RETURN NULL;
            END $$
        """)
        op.execute(
            f"CREATE TRIGGER mobile_hook_fact_{action}_epoch AFTER {action.upper()} ON mobile_hook_evidence_events "
            f"REFERENCING {'NEW' if action == 'insert' else 'OLD'} TABLE AS {relation} FOR EACH STATEMENT "
            f"EXECUTE FUNCTION mobile_hook_fact_epoch_{action}()"
        )


def downgrade():
    for action in ("insert", "delete"):
        op.execute(f"DROP TRIGGER mobile_hook_fact_{action}_epoch ON mobile_hook_evidence_events")
        op.execute(f"DROP FUNCTION mobile_hook_fact_epoch_{action}()")
    op.execute("DROP TRIGGER mobile_hook_review_epoch ON hook_versions")
    op.execute("DROP TRIGGER mobile_hook_visibility_epoch ON hook_listings")
    op.execute("DROP TRIGGER mobile_hook_delete_epoch ON hook_listings")
    op.execute("DROP FUNCTION mobile_bump_hook_scope_epochs()")
    op.drop_table("mobile_hook_evidence_events")
    op.drop_table("mobile_hook_layer_components")
    op.drop_column("mobile_verified_layers", "expected_hooks")
