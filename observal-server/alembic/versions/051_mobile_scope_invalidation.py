# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Invalidate subject cursors on listing visibility/review changes and deny on user deletion.

Revision ID: 051_mobile_scope_invalidation
Revises: 050_mobile_scope_epochs
"""

from alembic import op

revision = "051_mobile_scope_invalidation"
down_revision = "050_mobile_scope_epochs"
branch_labels = None
depends_on = None


def upgrade():
    op.execute("""
        CREATE FUNCTION mobile_bump_mcp_scope_epochs() RETURNS trigger LANGUAGE plpgsql AS $$
        DECLARE target uuid;
        BEGIN
            target := CASE WHEN TG_TABLE_NAME = 'mcp_listings' THEN NEW.id ELSE NEW.listing_id END;
            INSERT INTO mobile_scope_epochs(project_id,subject_id,scope,epoch)
            SELECT DISTINCT e.project_id,e.user_id,'user',1 FROM mobile_evidence_events e
            WHERE e.component_id=target
            ON CONFLICT (project_id,subject_id,scope) DO UPDATE SET epoch=mobile_scope_epochs.epoch+1;
            INSERT INTO mobile_scope_epochs(project_id,subject_id,scope,epoch)
            SELECT DISTINCT e.project_id,p.original_author_id,'author',1
            FROM mobile_evidence_events e JOIN mobile_listing_provenance p
              ON p.kind='mcp' AND p.listing_id=e.component_id
            WHERE e.component_id=target
            ON CONFLICT (project_id,subject_id,scope) DO UPDATE SET epoch=mobile_scope_epochs.epoch+1;
            RETURN NEW;
        END $$
    """)
    op.execute("""
        CREATE TRIGGER mobile_visibility_epoch AFTER UPDATE OF is_private ON mcp_listings
        FOR EACH ROW WHEN (OLD.is_private IS DISTINCT FROM NEW.is_private)
        EXECUTE FUNCTION mobile_bump_mcp_scope_epochs()
    """)
    op.execute("""
        CREATE TRIGGER mobile_review_epoch AFTER UPDATE OF status ON mcp_versions
        FOR EACH ROW WHEN (OLD.status IS DISTINCT FROM NEW.status)
        EXECUTE FUNCTION mobile_bump_mcp_scope_epochs()
    """)
    op.execute("""
        CREATE FUNCTION mobile_deny_before_user_delete() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            PERFORM pg_advisory_xact_lock(hashtextextended('mobile-read:default', 0));
            INSERT INTO mobile_read_controls(project_id,blocked,generation)
            VALUES ('default',true,1) ON CONFLICT (project_id) DO UPDATE
            SET blocked=true,generation=mobile_read_controls.generation+1,updated_at=now();
            RETURN OLD;
        END $$
    """)
    op.execute("""
        CREATE TRIGGER mobile_deny_erasure BEFORE DELETE ON users
        FOR EACH ROW EXECUTE FUNCTION mobile_deny_before_user_delete()
    """)


def downgrade():
    op.execute("DROP TRIGGER mobile_deny_erasure ON users")
    op.execute("DROP FUNCTION mobile_deny_before_user_delete()")
    op.execute("DROP TRIGGER mobile_review_epoch ON mcp_versions")
    op.execute("DROP TRIGGER mobile_visibility_epoch ON mcp_listings")
    op.execute("DROP FUNCTION mobile_bump_mcp_scope_epochs()")
