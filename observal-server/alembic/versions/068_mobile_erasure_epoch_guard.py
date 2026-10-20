# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Prevent erased Pi principals from being recreated as scoped epoch FK rows.

Revision ID: 068_mobile_erasure_epoch_guard
Revises: 067_mobile_short_retention_fence
"""

import sqlalchemy as sa

from alembic import op

revision = "068_mobile_erasure_epoch_guard"
down_revision = "067_mobile_short_retention_fence"
branch_labels = None
depends_on = None


def upgrade():
    # 067 ingest receipts have no user FK. A previously erased account may
    # already have left person-linked session/hash metadata behind. Remove
    # only orphaned receipts, then make subsequent erasures cascade both
    # tables in the same transaction as users and the read barrier.
    for table in ("mobile_source_final_receipts", "mobile_source_line_highwater"):
        op.execute(f"DELETE FROM {table} receipts WHERE NOT EXISTS (SELECT 1 FROM users WHERE id=receipts.user_id)")
        op.create_foreign_key(f"fk_{table}_user_erasure", table, "users", ["user_id"], ["id"], ondelete="CASCADE")
    # An opaque skip count lets the scanner advance past >50 erased CH keys
    # without persisting a deleted person's user/session as the checkpoint.
    op.add_column(
        "mobile_backfill_cursor", sa.Column("skip_count", sa.BigInteger(), nullable=False, server_default="0")
    )
    op.execute("""
        ALTER TABLE mobile_backfill_cursor ADD CONSTRAINT ck_mobile_backfill_skip_nonnegative CHECK (skip_count>=0)
    """)
    # Existing 067 checkpoints may already name a deleted person; a future
    # DELETE trigger cannot remove historical orphans on its own.
    op.execute("""
        UPDATE mobile_backfill_cursor SET project_id='',user_id='',session_id='',skip_count=0
        WHERE user_id<>'' AND NOT EXISTS (SELECT 1 FROM users WHERE users.id::text=mobile_backfill_cursor.user_id)
    """)
    # The singleton backfill key is a textual actor/session checkpoint, not
    # a user FK. A deleted user's key must never linger in an idle scanner.
    op.execute("""
        CREATE FUNCTION mobile_erase_user_backfill_cursor() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          UPDATE mobile_backfill_cursor SET project_id='',user_id='',session_id='',skip_count=0
          WHERE singleton=true AND user_id=OLD.id::text;
          RETURN OLD;
        END $$
    """)
    op.execute("""
        CREATE TRIGGER mobile_erase_user_backfill_cursor AFTER DELETE ON users
        FOR EACH ROW EXECUTE FUNCTION mobile_erase_user_backfill_cursor()
    """)
    # Erasing a user cascades runs, publications, all three typed facts,
    # mappings and zero cohorts. Their older BEFORE/AFTER triggers may try
    # to insert an epoch for the now-erased subject. A centralized guard
    # covers every such trigger, including future typed evidence kinds.
    # KEY SHARE serializes a concurrent erasure so a survivor cannot be
    # removed between this check and its new epoch FK insertion.
    op.execute("""
        CREATE FUNCTION mobile_epoch_surviving_subject() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          PERFORM 1 FROM users WHERE id=NEW.subject_id FOR KEY SHARE;
          IF NOT FOUND THEN RETURN NULL; END IF;
          RETURN NEW;
        END $$
    """)
    op.execute("""
        CREATE TRIGGER mobile_epoch_surviving_subject BEFORE INSERT ON mobile_scope_epochs
        FOR EACH ROW EXECUTE FUNCTION mobile_epoch_surviving_subject()
    """)
    # An actor's run/publication AFTER DELETE also bumps Author scopes. Skip
    # only already-erased subjects; living authors must keep invalidation.
    op.execute("""
        CREATE OR REPLACE FUNCTION mobile_bump_actor_source_scopes_for(project text, actor uuid)
        RETURNS void LANGUAGE plpgsql AS $$
        BEGIN
          INSERT INTO mobile_scope_epochs(project_id,subject_id,scope,epoch)
          SELECT project,actor,'user',1 FROM users WHERE id=actor
          ON CONFLICT (project_id,subject_id,scope) DO UPDATE SET epoch=mobile_scope_epochs.epoch+1;
          INSERT INTO mobile_scope_epochs(project_id,subject_id,scope,epoch)
          SELECT links.project_id,links.author_id,'author',1 FROM mobile_author_actor_links links
          JOIN users surviving ON surviving.id=links.author_id
          WHERE links.project_id=project AND links.actor_id=actor
          ON CONFLICT (project_id,subject_id,scope) DO UPDATE SET epoch=mobile_scope_epochs.epoch+1;
        END $$
    """)


def downgrade():
    # The 067 predecessor permits user deletion but can fail the FK after a
    # source/fact cascade. Data-free rollback does not make future 067 user
    # erasures safe. Never expose a remotely callable broken erasure again.
    raise RuntimeError("Cannot restore unsafe pre-068 mobile erasure triggers; fix forward")
