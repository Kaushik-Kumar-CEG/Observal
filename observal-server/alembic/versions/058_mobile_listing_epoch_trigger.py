# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Repair listing/review cursor invalidation on distinct PostgreSQL row shapes.

Revision ID: 058_mobile_listing_epoch
Revises: 057_mobile_pi_parent
"""

from alembic import op

revision = "058_mobile_listing_epoch"
down_revision = "057_mobile_pi_parent"
branch_labels = None
depends_on = None


def upgrade():
    # PL/pgSQL CASE compiles both NEW.id and NEW.listing_id against the
    # current trigger record, even if the other branch is never selected.
    # An UPDATE mcp_listings.is_private used to fail before bumping any epoch.
    op.execute("""
        CREATE OR REPLACE FUNCTION mobile_bump_mcp_scope_epochs() RETURNS trigger LANGUAGE plpgsql AS $$
        DECLARE target uuid;
        BEGIN
            IF TG_TABLE_NAME = 'mcp_listings' THEN
                target := NEW.id;
            ELSE
                target := NEW.listing_id;
            END IF;
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


def downgrade():
    # Keep the repaired security trigger through a test-only rollback. The
    # 051 downgrade removes the function when undoing the entire feature.
    pass
