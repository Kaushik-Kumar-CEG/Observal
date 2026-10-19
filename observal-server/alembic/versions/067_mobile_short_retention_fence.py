# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Fence mobile facts across independent ClickHouse source-retention transitions.

Revision ID: 067_mobile_short_retention_fence
Revises: 066_mobile_scope_retention_clock
"""

import sqlalchemy as sa

from alembic import op

revision = "067_mobile_short_retention_fence"
down_revision = "066_mobile_scope_retention_clock"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "mobile_read_controls",
        sa.Column("source_policy_ready", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column(
        "mobile_read_controls", sa.Column("source_policy_epoch", sa.BigInteger(), nullable=False, server_default="1")
    )
    op.add_column("mobile_read_controls", sa.Column("source_policy_since", sa.DateTime(timezone=True)))
    op.add_column(
        "mobile_session_publications",
        sa.Column("source_policy_epoch", sa.BigInteger(), nullable=False, server_default="0"),
    )
    op.add_column("mobile_session_publications", sa.Column("source_highest_line", sa.BigInteger()))
    # A durable ingest-side maximum prevents user-supplied integrity-repair
    # requests from rewinding the ClickHouse checkpoint and concealing a
    # later source record that whole-row TTL erased.
    op.create_table(
        "mobile_source_line_highwater",
        sa.Column("project_id", sa.String(64), primary_key=True),
        sa.Column("user_id", sa.Uuid(), primary_key=True),
        sa.Column("harness", sa.String(32), primary_key=True),
        sa.Column("session_id", sa.String(256), primary_key=True),
        sa.Column("max_line", sa.BigInteger(), nullable=False),
        sa.CheckConstraint("max_line>=0", name="ck_mobile_source_highwater_nonnegative"),
    )
    op.create_table(
        "mobile_source_final_receipts",
        sa.Column("project_id", sa.String(64), primary_key=True),
        sa.Column("user_id", sa.Uuid(), primary_key=True),
        sa.Column("harness", sa.String(32), primary_key=True),
        sa.Column("session_id", sa.String(256), primary_key=True),
        sa.Column("final_line", sa.BigInteger(), nullable=False),
        sa.Column("source_hash", sa.String(64), nullable=False),
        sa.CheckConstraint("final_line>=0", name="ck_mobile_final_line_nonnegative"),
    )
    op.execute("""
        CREATE FUNCTION mobile_source_highwater_monotonic() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          IF NEW.max_line<OLD.max_line THEN
            RAISE EXCEPTION 'Mobile source high-water cannot decrease' USING ERRCODE='23514';
          END IF;
          RETURN NEW;
        END $$
    """)
    op.execute("""
        CREATE TRIGGER mobile_source_highwater_guard BEFORE UPDATE OF max_line ON mobile_source_line_highwater
        FOR EACH ROW EXECUTE FUNCTION mobile_source_highwater_monotonic()
    """)
    op.execute("""
        CREATE FUNCTION mobile_bump_source_highwater_epoch() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          IF TG_OP='UPDATE' AND to_jsonb(OLD)=to_jsonb(NEW) THEN RETURN NEW; END IF;
          INSERT INTO mobile_scope_epochs(project_id,subject_id,scope,epoch)
          VALUES (NEW.project_id,NEW.user_id,'user',1)
          ON CONFLICT (project_id,subject_id,scope) DO UPDATE SET epoch=mobile_scope_epochs.epoch+1;
          INSERT INTO mobile_scope_epochs(project_id,subject_id,scope,epoch)
          SELECT NEW.project_id,author_id,'author',1 FROM mobile_author_actor_links
          WHERE project_id=NEW.project_id AND actor_id=NEW.user_id
          ON CONFLICT (project_id,subject_id,scope) DO UPDATE SET epoch=mobile_scope_epochs.epoch+1;
          RETURN NEW;
        END $$
    """)
    op.execute("""
        CREATE TRIGGER mobile_source_highwater_epoch AFTER INSERT OR UPDATE OF max_line ON mobile_source_line_highwater
        FOR EACH ROW EXECUTE FUNCTION mobile_bump_source_highwater_epoch()
    """)
    op.execute("""
        CREATE TRIGGER mobile_source_final_epoch AFTER INSERT OR UPDATE ON mobile_source_final_receipts
        FOR EACH ROW EXECUTE FUNCTION mobile_bump_source_highwater_epoch()
    """)
    op.create_table(
        "mobile_source_policy_audit",
        sa.Column("id", sa.BigInteger(), sa.Identity(), primary_key=True),
        sa.Column("project_id", sa.String(64), nullable=False),
        sa.Column("source_policy_epoch", sa.BigInteger(), nullable=False),
        sa.Column("event", sa.String(24), nullable=False),
        sa.Column("retention_days", sa.Integer()),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index(
        "ix_mobile_source_policy_audit_epoch", "mobile_source_policy_audit", ["project_id", "source_policy_epoch"]
    )
    op.create_index(
        "ix_mobile_pub_policy_recheck",
        "mobile_session_publications",
        ["source_policy_epoch", "status", "last_checked_at"],
    )
    # Old 066 API replicas only consult blocked; close them before any
    # non-transactional ClickHouse policy change or rolling API replacement.
    # An existing opened cohort must undergo audited revoke, not silent reopen.
    op.execute("UPDATE mobile_read_controls SET blocked=true,generation=generation+1,updated_at=clock_timestamp()")
    # Old 066 publications have no history of past ClickHouse whole-row TTL
    # changes; epoch zero is quarantined until the worker rereads their whole
    # source from ClickHouse AFTER the current TTL has been verified.
    # Existing receipts and facts remain intact. No unbounded table rewrite.
    op.execute("""
        CREATE FUNCTION mobile_fence_source_policy_setting() RETURNS trigger LANGUAGE plpgsql AS $$
        DECLARE applied_epoch bigint;
        BEGIN
          IF TG_OP='UPDATE' AND OLD.key=NEW.key AND OLD.value IS NOT DISTINCT FROM NEW.value THEN
            RETURN NEW;
          END IF;
          PERFORM pg_advisory_xact_lock(hashtextextended('mobile-read:default',0));
          UPDATE mobile_read_controls SET blocked=true,source_policy_ready=false,source_policy_since=NULL,
            source_policy_epoch=source_policy_epoch+1,generation=generation+1,
            updated_at=clock_timestamp() WHERE project_id='default' RETURNING source_policy_epoch INTO applied_epoch;
          INSERT INTO mobile_source_policy_audit(project_id,source_policy_epoch,event,retention_days)
          VALUES ('default',applied_epoch,'setting_changed',
            CASE WHEN TG_OP!='DELETE' AND NEW.key='data.retention_days'
              AND NEW.value ~ '^[0-9]{1,8}$' THEN NEW.value::integer ELSE NULL END);
          IF TG_OP='DELETE' THEN RETURN OLD; END IF;
          RETURN NEW;
        END $$
    """)
    op.execute("""
        CREATE TRIGGER mobile_source_policy_insert AFTER INSERT ON enterprise_config
        FOR EACH ROW WHEN (NEW.key='data.retention_days') EXECUTE FUNCTION mobile_fence_source_policy_setting()
    """)
    op.execute("""
        CREATE TRIGGER mobile_source_policy_update AFTER UPDATE ON enterprise_config
        FOR EACH ROW WHEN (OLD.key='data.retention_days' OR NEW.key='data.retention_days')
        EXECUTE FUNCTION mobile_fence_source_policy_setting()
    """)
    op.execute("""
        CREATE TRIGGER mobile_source_policy_delete AFTER DELETE ON enterprise_config
        FOR EACH ROW WHEN (OLD.key='data.retention_days') EXECUTE FUNCTION mobile_fence_source_policy_setting()
    """)


def downgrade():
    bind = op.get_bind()
    if (
        bind.scalar(sa.text("SELECT EXISTS (SELECT 1 FROM mobile_source_policy_audit)"))
        or bind.scalar(sa.text("SELECT EXISTS (SELECT 1 FROM mobile_read_controls WHERE source_policy_epoch>1)"))
        or bind.scalar(sa.text("SELECT EXISTS (SELECT 1 FROM mobile_session_publications)"))
        or bind.scalar(sa.text("SELECT EXISTS (SELECT 1 FROM mobile_operator_audit)"))
        or bind.scalar(sa.text("SELECT EXISTS (SELECT 1 FROM mobile_source_line_highwater)"))
        or bind.scalar(sa.text("SELECT EXISTS (SELECT 1 FROM mobile_source_final_receipts)"))
    ):
        raise RuntimeError("Cannot discard committed mobile source policy epochs or qualified receipts")
    op.execute("DROP TRIGGER mobile_source_policy_delete ON enterprise_config")
    op.execute("DROP TRIGGER mobile_source_policy_update ON enterprise_config")
    op.execute("DROP TRIGGER mobile_source_policy_insert ON enterprise_config")
    op.execute("DROP FUNCTION mobile_fence_source_policy_setting()")
    op.drop_index("ix_mobile_pub_policy_recheck", table_name="mobile_session_publications")
    op.drop_index("ix_mobile_source_policy_audit_epoch", table_name="mobile_source_policy_audit")
    op.drop_table("mobile_source_policy_audit")
    op.execute("DROP TRIGGER mobile_source_highwater_epoch ON mobile_source_line_highwater")
    op.execute("DROP TRIGGER mobile_source_final_epoch ON mobile_source_final_receipts")
    op.execute("DROP FUNCTION mobile_bump_source_highwater_epoch()")
    op.drop_table("mobile_source_final_receipts")
    op.execute("DROP TRIGGER mobile_source_highwater_guard ON mobile_source_line_highwater")
    op.execute("DROP FUNCTION mobile_source_highwater_monotonic()")
    op.drop_table("mobile_source_line_highwater")
    op.drop_column("mobile_session_publications", "source_highest_line")
    op.drop_column("mobile_session_publications", "source_policy_epoch")
    op.drop_column("mobile_read_controls", "source_policy_since")
    op.drop_column("mobile_read_controls", "source_policy_epoch")
    op.drop_column("mobile_read_controls", "source_policy_ready")
