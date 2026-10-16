# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Uploader-bound Pi skill pins and result-linked root facts, never legacy backfill.

Revision ID: 059_mobile_pi_skill_facts
Revises: 058_mobile_listing_epoch
"""

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

from alembic import op

revision = "059_mobile_pi_skill_facts"
down_revision = "058_mobile_listing_epoch"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "mobile_verified_layers",
        sa.Column("expected_skills", sa.SmallInteger(), nullable=False, server_default="0"),
    )
    op.create_table(
        "mobile_skill_layer_components",
        sa.Column("project_id", sa.String(64), primary_key=True),
        sa.Column("user_id", UUID(as_uuid=True), primary_key=True),
        sa.Column("harness", sa.String(32), primary_key=True),
        sa.Column("layer_hash", sa.String(67), primary_key=True),
        sa.Column("scope", sa.String(8), primary_key=True),
        sa.Column("alias", sa.String(128), primary_key=True),
        sa.Column(
            "component_id", UUID(as_uuid=True), sa.ForeignKey("skill_listings.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column(
            "version_id", UUID(as_uuid=True), sa.ForeignKey("skill_versions.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("location_sha256", sa.String(64), nullable=False),
        sa.Column("content_sha256", sa.String(64), nullable=False),
        sa.CheckConstraint("scope IN ('user','project')", name="ck_mobile_skill_scope"),
        sa.UniqueConstraint(
            "project_id",
            "user_id",
            "harness",
            "layer_hash",
            "scope",
            "alias",
            "component_id",
            name="uq_mobile_skill_mapping_component",
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
        "mobile_skill_evidence_events",
        sa.Column("project_id", sa.String(64), primary_key=True),
        sa.Column("user_id", UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("harness", sa.String(32), primary_key=True),
        sa.Column("session_id", sa.String(256), primary_key=True),
        sa.Column("source_line_offset", sa.Integer(), primary_key=True),
        sa.Column("block_key", sa.String(270), primary_key=True),
        sa.Column("layer_hash", sa.String(67), nullable=False),
        sa.Column("scope", sa.String(8), nullable=False),
        sa.Column("alias", sa.String(128), nullable=False),
        sa.Column(
            "component_id", UUID(as_uuid=True), sa.ForeignKey("skill_listings.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("source_revision", sa.String(64), nullable=False),
        sa.Column("run_incarnation", UUID(as_uuid=True), nullable=False),
        sa.Column("root_session_id", sa.String(256), nullable=False),
        sa.Column("root_run_incarnation", UUID(as_uuid=True), nullable=False),
        sa.Column("event_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("result_state", sa.String(16), nullable=False, server_default="success"),
        sa.CheckConstraint("result_state='success'", name="ck_mobile_skill_success_only"),
        sa.ForeignKeyConstraint(
            ["project_id", "user_id", "harness", "layer_hash", "scope", "alias", "component_id"],
            [
                "mobile_skill_layer_components.project_id",
                "mobile_skill_layer_components.user_id",
                "mobile_skill_layer_components.harness",
                "mobile_skill_layer_components.layer_hash",
                "mobile_skill_layer_components.scope",
                "mobile_skill_layer_components.alias",
                "mobile_skill_layer_components.component_id",
            ],
            ondelete="CASCADE",
        ),
    )
    op.create_index("ix_mobile_skill_actor_time", "mobile_skill_evidence_events", ["user_id", "event_time"])
    op.create_index("ix_mobile_skill_component_time", "mobile_skill_evidence_events", ["component_id", "event_time"])
    # Epochs are bumped even for a listing that becomes private or a version
    # whose review is revoked. Existing authorized cards/cursors must go stale.
    op.execute("""
        CREATE FUNCTION mobile_bump_skill_scope_epochs() RETURNS trigger LANGUAGE plpgsql AS $$
        DECLARE target uuid;
        BEGIN
            IF TG_TABLE_NAME = 'skill_listings' THEN
                target := CASE WHEN TG_OP='DELETE' THEN OLD.id ELSE NEW.id END;
            ELSE
                target := NEW.listing_id;
            END IF;
            INSERT INTO mobile_scope_epochs(project_id,subject_id,scope,epoch)
            SELECT DISTINCT e.project_id,e.user_id,'user',1 FROM mobile_skill_evidence_events e
            WHERE e.component_id=target
            ON CONFLICT (project_id,subject_id,scope) DO UPDATE SET epoch=mobile_scope_epochs.epoch+1;
            INSERT INTO mobile_scope_epochs(project_id,subject_id,scope,epoch)
            SELECT DISTINCT e.project_id,p.original_author_id,'author',1
            FROM mobile_skill_evidence_events e JOIN mobile_listing_provenance p
              ON p.kind='skill' AND p.listing_id=e.component_id
            WHERE e.component_id=target
            ON CONFLICT (project_id,subject_id,scope) DO UPDATE SET epoch=mobile_scope_epochs.epoch+1;
            IF TG_OP='DELETE' THEN RETURN OLD; END IF;
            RETURN NEW;
        END $$
    """)
    # A listing deletion cascades its pins and facts. Bump before either the
    # provenance marker or the facts can disappear; no stale signed cursor.
    op.execute(
        "CREATE TRIGGER mobile_skill_delete_epoch BEFORE DELETE ON skill_listings "
        "FOR EACH ROW EXECUTE FUNCTION mobile_bump_skill_scope_epochs()"
    )
    for action, relation in (("insert", "new_events"), ("delete", "old_events")):
        op.execute(f"""
            CREATE FUNCTION mobile_skill_fact_epoch_{action}() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
                INSERT INTO mobile_scope_epochs(project_id,subject_id,scope,epoch)
                SELECT DISTINCT project_id,user_id,'user',1 FROM {relation}
                ON CONFLICT (project_id,subject_id,scope) DO UPDATE SET epoch=mobile_scope_epochs.epoch+1;
                INSERT INTO mobile_scope_epochs(project_id,subject_id,scope,epoch)
                SELECT DISTINCT e.project_id,p.original_author_id,'author',1 FROM {relation} e
                JOIN mobile_listing_provenance p ON p.kind='skill' AND p.listing_id=e.component_id
                JOIN users u ON u.id=p.original_author_id
                ON CONFLICT (project_id,subject_id,scope) DO UPDATE SET epoch=mobile_scope_epochs.epoch+1;
                RETURN NULL;
            END $$
        """)
        op.execute(
            f"CREATE TRIGGER mobile_skill_fact_{action}_epoch AFTER {action.upper()} ON mobile_skill_evidence_events "
            f"REFERENCING {'NEW' if action == 'insert' else 'OLD'} TABLE AS {relation} FOR EACH STATEMENT "
            f"EXECUTE FUNCTION mobile_skill_fact_epoch_{action}()"
        )
    op.execute(
        "CREATE TRIGGER mobile_skill_visibility_epoch AFTER UPDATE OF is_private ON skill_listings "
        "FOR EACH ROW WHEN (OLD.is_private IS DISTINCT FROM NEW.is_private) "
        "EXECUTE FUNCTION mobile_bump_skill_scope_epochs()"
    )
    op.execute(
        "CREATE TRIGGER mobile_skill_review_epoch AFTER UPDATE OF status ON skill_versions "
        "FOR EACH ROW WHEN (OLD.status IS DISTINCT FROM NEW.status) "
        "EXECUTE FUNCTION mobile_bump_skill_scope_epochs()"
    )


def downgrade():
    op.execute("DROP TRIGGER mobile_skill_review_epoch ON skill_versions")
    op.execute("DROP TRIGGER IF EXISTS mobile_skill_delete_epoch ON skill_listings")
    for action in ("insert", "delete"):
        op.execute(f"DROP TRIGGER IF EXISTS mobile_skill_fact_{action}_epoch ON mobile_skill_evidence_events")
        op.execute(f"DROP FUNCTION IF EXISTS mobile_skill_fact_epoch_{action}()")
    op.execute("DROP TRIGGER mobile_skill_visibility_epoch ON skill_listings")
    op.execute("DROP FUNCTION mobile_bump_skill_scope_epochs()")
    op.drop_table("mobile_skill_evidence_events")
    op.drop_table("mobile_skill_layer_components")
    op.drop_column("mobile_verified_layers", "expected_skills")
