# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Index per-scope retention clocks and invalidate descendant cursors on source writes.

Revision ID: 066_mobile_scope_retention_clock
Revises: 065_mobile_synthetic_deadline
"""

import sqlalchemy as sa

from alembic import op

revision = "066_mobile_scope_retention_clock"
down_revision = "065_mobile_synthetic_deadline"
branch_labels = None
depends_on = None

_EVENTS = (
    ("mcp", "mobile_evidence_events"),
    ("skill", "mobile_skill_evidence_events"),
    ("hook", "mobile_hook_evidence_events"),
)


def upgrade():
    # Actor links are an overapproximation: an original author may retain an
    # actor after its last fact is deleted. Extra stale cursors are safe; a
    # missing link could leave a changed Author page falsely current.
    op.create_table(
        "mobile_author_actor_links",
        sa.Column("project_id", sa.String(64), primary_key=True),
        sa.Column("author_id", sa.Uuid(), sa.ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("actor_id", sa.Uuid(), sa.ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
    )
    op.create_index(
        "ix_mobile_author_actor_reverse", "mobile_author_actor_links", ["project_id", "actor_id", "author_id"]
    )
    op.create_index(
        "ix_mobile_publication_scope_clock",
        "mobile_session_publications",
        ["project_id", "user_id", "source_retained_until"],
        postgresql_where=sa.text("source_retained_until IS NOT NULL AND status IN ('complete','partial')"),
    )
    # Transaction-level serialization occurs BEFORE existing fact epoch
    # triggers. Locking only in AFTER triggers could invert the epoch/listing
    # order across a fact batch and delayed provenance insert, deadlocking.
    # One statement-level lock, not a row-level or recursive reader lock.
    # This deliberately serializes typed fact writers; measure ingest load
    # separately, never infer a product latency pass from the read benchmark.
    op.execute("""
        CREATE FUNCTION mobile_author_link_write_gate() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          PERFORM pg_advisory_xact_lock(hashtextextended('mobile-author-link-writes',0));
          RETURN NULL;
        END $$
    """)
    for _kind, events in _EVENTS:
        op.execute(
            f"CREATE TRIGGER mobile_author_link_write_gate BEFORE INSERT OR UPDATE OR DELETE ON {events} "
            "FOR EACH STATEMENT EXECUTE FUNCTION mobile_author_link_write_gate()"
        )
    op.execute(
        "CREATE TRIGGER mobile_provenance_write_gate BEFORE INSERT OR DELETE ON mobile_listing_provenance "
        "FOR EACH STATEMENT EXECUTE FUNCTION mobile_author_link_write_gate()"
    )
    # A listing DELETE must acquire the same gate before locking its FK row;
    # otherwise a fact insert can hold the gate while waiting on that row and
    # the listing's cascade can wait on provenance's gate in reverse order.
    for listing in ("mcp_listings", "skill_listings", "hook_listings"):
        op.execute(
            f"CREATE TRIGGER mobile_listing_delete_gate BEFORE DELETE ON {listing} "
            "FOR EACH STATEMENT EXECUTE FUNCTION mobile_author_link_write_gate()"
        )
    # User erasure also cascades provenance/facts: take the gate before the
    # user's FK row lock or fact insertion can form the same lock inversion.
    op.execute(
        "CREATE TRIGGER mobile_user_delete_gate BEFORE DELETE ON users "
        "FOR EACH STATEMENT EXECUTE FUNCTION mobile_author_link_write_gate()"
    )
    for kind, events in _EVENTS:
        op.execute(f"""
            INSERT INTO mobile_author_actor_links(project_id,author_id,actor_id)
            SELECT DISTINCT e.project_id,p.original_author_id,e.user_id FROM {events} e
            JOIN mobile_listing_provenance p ON p.kind='{kind}' AND p.listing_id=e.component_id
            ON CONFLICT DO NOTHING
        """)
        for action in ("insert", "update"):
            update_epochs = (
                f"""
                  -- An UPDATE may move an event between windows, actors or
                  -- listings; invalidate BOTH old and new User/Author scopes.
                  INSERT INTO mobile_scope_epochs(project_id,subject_id,scope,epoch)
                  SELECT project_id,user_id,'user',1 FROM old_events
                  UNION SELECT project_id,user_id,'user',1 FROM new_events
                  ON CONFLICT (project_id,subject_id,scope) DO UPDATE SET epoch=mobile_scope_epochs.epoch+1;
                  INSERT INTO mobile_scope_epochs(project_id,subject_id,scope,epoch)
                  SELECT DISTINCT e.project_id,p.original_author_id,'author',1 FROM old_events e
                  JOIN mobile_listing_provenance p ON p.kind='{kind}' AND p.listing_id=e.component_id
                  UNION SELECT DISTINCT e.project_id,p.original_author_id,'author',1 FROM new_events e
                  JOIN mobile_listing_provenance p ON p.kind='{kind}' AND p.listing_id=e.component_id
                  ON CONFLICT (project_id,subject_id,scope) DO UPDATE SET epoch=mobile_scope_epochs.epoch+1;
                """
                if action == "update"
                else ""
            )
            op.execute(f"""
                CREATE FUNCTION mobile_link_{kind}_actor_{action}() RETURNS trigger LANGUAGE plpgsql AS $$
                BEGIN
                  INSERT INTO mobile_author_actor_links(project_id,author_id,actor_id)
                  SELECT DISTINCT e.project_id,p.original_author_id,e.user_id FROM new_events e
                  JOIN mobile_listing_provenance p ON p.kind='{kind}' AND p.listing_id=e.component_id
                  ON CONFLICT DO NOTHING;
                  -- A previous fact-epoch trigger can run before the
                  -- provenance transaction commits. Bump after this lock.
                  INSERT INTO mobile_scope_epochs(project_id,subject_id,scope,epoch)
                  SELECT DISTINCT e.project_id,p.original_author_id,'author',1 FROM new_events e
                  JOIN mobile_listing_provenance p ON p.kind='{kind}' AND p.listing_id=e.component_id
                  ON CONFLICT (project_id,subject_id,scope) DO UPDATE SET epoch=mobile_scope_epochs.epoch+1;
                  {update_epochs}
                  RETURN NULL;
                END $$
            """)
            transition = (
                "OLD TABLE AS old_events NEW TABLE AS new_events" if action == "update" else "NEW TABLE AS new_events"
            )
            op.execute(
                f"CREATE TRIGGER mobile_link_{kind}_actor_{action}_trigger AFTER {action.upper()} ON {events} "
                f"REFERENCING {transition} FOR EACH STATEMENT "
                f"EXECUTE FUNCTION mobile_link_{kind}_actor_{action}()"
            )
    # Provenance normally precedes projection; still cover delayed original-
    # author capture. An original author is immutable, not a transferable owner.
    unions = " UNION ALL ".join(
        f"SELECT DISTINCT e.project_id,NEW.original_author_id AS author_id,e.user_id AS actor_id "
        f"FROM {events} e WHERE NEW.kind='{kind}' AND e.component_id=NEW.listing_id"
        for kind, events in _EVENTS
    )
    op.execute(f"""
        CREATE FUNCTION mobile_link_on_provenance() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          INSERT INTO mobile_author_actor_links(project_id,author_id,actor_id)
          SELECT DISTINCT project_id,author_id,actor_id FROM ({unions}) linked
          ON CONFLICT DO NOTHING;
          -- Delayed capture makes facts newly visible to this Author.
          INSERT INTO mobile_scope_epochs(project_id,subject_id,scope,epoch)
          SELECT DISTINCT project_id,NEW.original_author_id,'author',1 FROM ({unions}) linked
          ON CONFLICT (project_id,subject_id,scope) DO UPDATE SET epoch=mobile_scope_epochs.epoch+1;
          INSERT INTO mobile_scope_epochs(project_id,subject_id,scope,epoch)
          SELECT DISTINCT project_id,actor_id,'user',1 FROM ({unions}) linked
          ON CONFLICT (project_id,subject_id,scope) DO UPDATE SET epoch=mobile_scope_epochs.epoch+1;
          RETURN NEW;
        END $$
    """)
    op.execute("""
        CREATE FUNCTION mobile_original_author_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          IF OLD.original_author_id IS DISTINCT FROM NEW.original_author_id THEN
            RAISE EXCEPTION 'Mobile original author is immutable' USING ERRCODE='23514';
          END IF;
          RETURN NEW;
        END $$
    """)
    op.execute(
        "CREATE TRIGGER mobile_original_author_immutable BEFORE UPDATE OF original_author_id "
        "ON mobile_listing_provenance FOR EACH ROW EXECUTE FUNCTION mobile_original_author_immutable()"
    )
    op.execute(
        "CREATE TRIGGER mobile_link_provenance AFTER INSERT "
        "ON mobile_listing_provenance FOR EACH ROW EXECUTE FUNCTION mobile_link_on_provenance()"
    )
    op.execute(f"""
        CREATE FUNCTION mobile_bump_provenance_delete() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          INSERT INTO mobile_scope_epochs(project_id,subject_id,scope,epoch)
          SELECT DISTINCT project_id,OLD.original_author_id,'author',1
          FROM ({unions.replace("NEW.", "OLD.")}) linked
          ON CONFLICT (project_id,subject_id,scope) DO UPDATE SET epoch=mobile_scope_epochs.epoch+1;
          INSERT INTO mobile_scope_epochs(project_id,subject_id,scope,epoch)
          SELECT DISTINCT project_id,actor_id,'user',1 FROM ({unions.replace("NEW.", "OLD.")}) linked
          ON CONFLICT (project_id,subject_id,scope) DO UPDATE SET epoch=mobile_scope_epochs.epoch+1;
          RETURN OLD;
        END $$
    """)
    op.execute(
        "CREATE TRIGGER mobile_bump_provenance_delete AFTER DELETE ON mobile_listing_provenance "
        "FOR EACH ROW EXECUTE FUNCTION mobile_bump_provenance_delete()"
    )
    # Replace the existing MCP-only account trigger function instead of
    # adding a second trigger with the opposite User/Author epoch lock order.
    # The existing trigger invokes the replacement on auth_provider updates.
    op.execute("""
        CREATE OR REPLACE FUNCTION mobile_epoch_actor_deactivation() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          IF (OLD.auth_provider='deactivated') IS DISTINCT FROM (NEW.auth_provider='deactivated') THEN
            INSERT INTO mobile_scope_epochs(project_id,subject_id,scope,epoch)
            SELECT DISTINCT project_id,actor_id,'user',1 FROM mobile_author_actor_links
            WHERE author_id=NEW.id ORDER BY project_id,actor_id
            ON CONFLICT (project_id,subject_id,scope) DO UPDATE SET epoch=mobile_scope_epochs.epoch+1;
            INSERT INTO mobile_scope_epochs(project_id,subject_id,scope,epoch)
            SELECT project_id,author_id,'author',1 FROM mobile_author_actor_links WHERE actor_id=NEW.id
            UNION SELECT project_id,NEW.id,'author',1 FROM mobile_author_actor_links WHERE author_id=NEW.id
            ON CONFLICT (project_id,subject_id,scope) DO UPDATE SET epoch=mobile_scope_epochs.epoch+1;
          END IF;
          RETURN NEW;
        END $$
    """)
    # The actor's self-User private facts disappear on ownership transfer,
    # even though the listing's privacy flag and the facts are unchanged.
    op.execute("""
        CREATE FUNCTION mobile_bump_private_owner_transfer() RETURNS trigger LANGUAGE plpgsql AS $$
        DECLARE events text;
        BEGIN
          events := CASE TG_TABLE_NAME
            WHEN 'mcp_listings' THEN 'mobile_evidence_events'
            WHEN 'skill_listings' THEN 'mobile_skill_evidence_events'
            WHEN 'hook_listings' THEN 'mobile_hook_evidence_events'
            ELSE NULL END;
          IF events IS NULL THEN RAISE EXCEPTION 'Invalid mobile owner epoch table'; END IF;
          EXECUTE format(
            'INSERT INTO mobile_scope_epochs(project_id,subject_id,scope,epoch) '
            ||'SELECT DISTINCT project_id,user_id,''user'',1 FROM %I WHERE component_id=$1 '
            ||'ON CONFLICT (project_id,subject_id,scope) DO UPDATE SET epoch=mobile_scope_epochs.epoch+1', events
          ) USING NEW.id;
          RETURN NEW;
        END $$
    """)
    for listing in ("mcp_listings", "skill_listings", "hook_listings"):
        op.execute(
            f"CREATE TRIGGER mobile_private_owner_transfer AFTER UPDATE OF submitted_by ON {listing} "
            "FOR EACH ROW WHEN (OLD.submitted_by IS DISTINCT FROM NEW.submitted_by "
            "AND (OLD.is_private OR NEW.is_private)) EXECUTE FUNCTION mobile_bump_private_owner_transfer()"
        )
    # No live ancestor traversal. Any run/publication transition for an actor
    # conservatively invalidates that actor's User scope and all Authors whose
    # component facts ever involved the actor. The existing MCP triggers may
    # also bump an epoch; revisions are opaque, so an extra increment is safe.
    op.execute("""
        CREATE FUNCTION mobile_bump_actor_source_scopes_for(project text, actor uuid) RETURNS void LANGUAGE plpgsql AS $$
        BEGIN
          INSERT INTO mobile_scope_epochs(project_id,subject_id,scope,epoch)
          VALUES (project,actor,'user',1)
          ON CONFLICT (project_id,subject_id,scope) DO UPDATE SET epoch=mobile_scope_epochs.epoch+1;
          INSERT INTO mobile_scope_epochs(project_id,subject_id,scope,epoch)
          SELECT project_id,author_id,'author',1 FROM mobile_author_actor_links
          WHERE project_id=project AND actor_id=actor
          ON CONFLICT (project_id,subject_id,scope) DO UPDATE SET epoch=mobile_scope_epochs.epoch+1;
        END $$
    """)
    op.execute("""
        CREATE FUNCTION mobile_bump_actor_source_scopes() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          IF TG_OP='DELETE' THEN
            PERFORM mobile_bump_actor_source_scopes_for(OLD.project_id,OLD.user_id);
            RETURN OLD;
          END IF;
          IF TG_OP='UPDATE' AND (OLD.project_id,OLD.user_id) IS DISTINCT FROM (NEW.project_id,NEW.user_id) THEN
            PERFORM mobile_bump_actor_source_scopes_for(OLD.project_id,OLD.user_id);
          END IF;
          PERFORM mobile_bump_actor_source_scopes_for(NEW.project_id,NEW.user_id);
          RETURN NEW;
        END $$
    """)
    for name, table, columns in (
        (
            "run",
            "mobile_run_instances",
            (
                "project_id",
                "user_id",
                "harness",
                "session_id",
                "run_incarnation",
                "header_hash",
                "started_at",
                "parent_session_id",
                "parent_run_incarnation",
                "parent_header_hash",
                "root_verified",
                "source_status",
            ),
        ),
        (
            "publication",
            "mobile_session_publications",
            ("project_id", "user_id", "harness", "session_id", "status", "source_revision", "source_retained_until"),
        ),
    ):
        op.execute(
            f"CREATE TRIGGER mobile_actor_{name}_epoch AFTER INSERT OR DELETE ON {table} "
            "FOR EACH ROW EXECUTE FUNCTION mobile_bump_actor_source_scopes()"
        )
        changed = " OR ".join(f"OLD.{col} IS DISTINCT FROM NEW.{col}" for col in columns)
        op.execute(
            f"CREATE TRIGGER mobile_actor_{name}_update_epoch AFTER UPDATE ON {table} "
            f"FOR EACH ROW WHEN ({changed}) EXECUTE FUNCTION mobile_bump_actor_source_scopes()"
        )


def downgrade():
    if op.get_bind().scalar(
        sa.text(
            "SELECT EXISTS (SELECT 1 FROM mobile_read_controls WHERE NOT blocked OR revocation_pending "
            "OR synthetic_expires_at IS NOT NULL)"
        )
    ):
        raise RuntimeError("Close and clear mobile cohorts before removing source-clock invalidation")
    op.execute("DROP TRIGGER mobile_actor_publication_update_epoch ON mobile_session_publications")
    op.execute("DROP TRIGGER mobile_actor_publication_epoch ON mobile_session_publications")
    op.execute("DROP TRIGGER mobile_actor_run_update_epoch ON mobile_run_instances")
    op.execute("DROP TRIGGER mobile_actor_run_epoch ON mobile_run_instances")
    op.execute("DROP FUNCTION mobile_bump_actor_source_scopes()")
    op.execute("DROP FUNCTION mobile_bump_actor_source_scopes_for(text,uuid)")
    for listing in ("hook_listings", "skill_listings", "mcp_listings"):
        op.execute(f"DROP TRIGGER mobile_private_owner_transfer ON {listing}")
    op.execute("DROP FUNCTION mobile_bump_private_owner_transfer()")
    # Restore the pre-066 MCP-only function before removing author-actor links.
    op.execute("""
        CREATE OR REPLACE FUNCTION mobile_epoch_actor_deactivation() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          IF (OLD.auth_provider='deactivated') IS DISTINCT FROM (NEW.auth_provider='deactivated') THEN
            INSERT INTO mobile_scope_epochs(project_id,subject_id,scope,epoch)
            SELECT DISTINCT e.project_id,p.original_author_id,'author',1
            FROM mobile_evidence_events e JOIN mobile_listing_provenance p
              ON p.kind='mcp' AND p.listing_id=e.component_id
            WHERE e.user_id=NEW.id
            ON CONFLICT (project_id,subject_id,scope) DO UPDATE SET epoch=mobile_scope_epochs.epoch+1;
          END IF;
          RETURN NEW;
        END $$
    """)
    op.execute("DROP TRIGGER mobile_bump_provenance_delete ON mobile_listing_provenance")
    op.execute("DROP FUNCTION mobile_bump_provenance_delete()")
    op.execute("DROP TRIGGER mobile_link_provenance ON mobile_listing_provenance")
    op.execute("DROP FUNCTION mobile_link_on_provenance()")
    op.execute("DROP TRIGGER mobile_original_author_immutable ON mobile_listing_provenance")
    op.execute("DROP FUNCTION mobile_original_author_immutable()")
    for kind, events in reversed(_EVENTS):
        for action in ("insert", "update"):
            op.execute(f"DROP TRIGGER mobile_link_{kind}_actor_{action}_trigger ON {events}")
            op.execute(f"DROP FUNCTION mobile_link_{kind}_actor_{action}()")
    op.execute("DROP TRIGGER mobile_user_delete_gate ON users")
    for listing in ("hook_listings", "skill_listings", "mcp_listings"):
        op.execute(f"DROP TRIGGER mobile_listing_delete_gate ON {listing}")
    op.execute("DROP TRIGGER mobile_provenance_write_gate ON mobile_listing_provenance")
    for _kind, events in reversed(_EVENTS):
        op.execute(f"DROP TRIGGER mobile_author_link_write_gate ON {events}")
    op.execute("DROP FUNCTION mobile_author_link_write_gate()")
    op.drop_index("ix_mobile_publication_scope_clock", table_name="mobile_session_publications")
    op.drop_index("ix_mobile_author_actor_reverse", table_name="mobile_author_actor_links")
    op.drop_table("mobile_author_actor_links")
