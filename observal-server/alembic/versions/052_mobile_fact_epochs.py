# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Invalidate only touched person's Author/User pages when facts change.

Revision ID: 052_mobile_fact_epochs
Revises: 051_mobile_scope_invalidation
"""

from alembic import op

revision = "052_mobile_fact_epochs"
down_revision = "051_mobile_scope_invalidation"
branch_labels = None
depends_on = None


def _bump_from_evidence(relation: str) -> str:
    # Transition relations are statement-level, deduplicated before epoch UPSERT.
    # An unrelated uploader/author never loses a cursor on another's ingest.
    return f"""
        INSERT INTO mobile_scope_epochs(project_id,subject_id,scope,epoch)
        SELECT DISTINCT project_id,user_id,'user',1 FROM {relation}
        ON CONFLICT (project_id,subject_id,scope) DO UPDATE
          SET epoch=mobile_scope_epochs.epoch+1;
        INSERT INTO mobile_scope_epochs(project_id,subject_id,scope,epoch)
        SELECT DISTINCT e.project_id,p.original_author_id,'author',1
        FROM {relation} e JOIN mobile_listing_provenance p
          ON p.kind='mcp' AND p.listing_id=e.component_id
        JOIN users u ON u.id=p.original_author_id
        ON CONFLICT (project_id,subject_id,scope) DO UPDATE
          SET epoch=mobile_scope_epochs.epoch+1;
    """


def upgrade():
    for action, relations in (
        ("insert", ("new_events",)),
        ("delete", ("old_events",)),
        ("update", ("old_events", "new_events")),
    ):
        op.execute(f"""
            CREATE FUNCTION mobile_epoch_evidence_{action}() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
                {"".join(_bump_from_evidence(rel) for rel in relations)}
                RETURN NULL;
            END $$
        """)
    op.execute("""
        CREATE TRIGGER mobile_epoch_event_insert AFTER INSERT ON mobile_evidence_events
        REFERENCING NEW TABLE AS new_events FOR EACH STATEMENT
        EXECUTE FUNCTION mobile_epoch_evidence_insert()
    """)
    op.execute("""
        CREATE TRIGGER mobile_epoch_event_delete AFTER DELETE ON mobile_evidence_events
        REFERENCING OLD TABLE AS old_events FOR EACH STATEMENT
        EXECUTE FUNCTION mobile_epoch_evidence_delete()
    """)
    op.execute("""
        CREATE TRIGGER mobile_epoch_event_update AFTER UPDATE ON mobile_evidence_events
        REFERENCING OLD TABLE AS old_events NEW TABLE AS new_events FOR EACH STATEMENT
        EXECUTE FUNCTION mobile_epoch_evidence_update()
    """)
    op.execute("""
        CREATE FUNCTION mobile_epoch_bound_run() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          IF OLD.root_verified IS DISTINCT FROM NEW.root_verified
             OR OLD.source_status IS DISTINCT FROM NEW.source_status THEN
            INSERT INTO mobile_scope_epochs(project_id,subject_id,scope,epoch)
            SELECT DISTINCT e.project_id,e.user_id,'user',1 FROM mobile_evidence_events e
            WHERE e.project_id=NEW.project_id AND e.user_id=NEW.user_id
              AND e.harness=NEW.harness AND e.root_run_incarnation=NEW.run_incarnation
            ON CONFLICT (project_id,subject_id,scope) DO UPDATE
              SET epoch=mobile_scope_epochs.epoch+1;
            INSERT INTO mobile_scope_epochs(project_id,subject_id,scope,epoch)
            SELECT DISTINCT e.project_id,p.original_author_id,'author',1
            FROM mobile_evidence_events e JOIN mobile_listing_provenance p
              ON p.kind='mcp' AND p.listing_id=e.component_id
            WHERE e.project_id=NEW.project_id AND e.user_id=NEW.user_id
              AND e.harness=NEW.harness AND e.root_run_incarnation=NEW.run_incarnation
            ON CONFLICT (project_id,subject_id,scope) DO UPDATE
              SET epoch=mobile_scope_epochs.epoch+1;
          END IF;
          RETURN NEW;
        END $$
    """)
    op.execute("""
        CREATE TRIGGER mobile_epoch_run AFTER UPDATE OF root_verified,source_status
        ON mobile_run_instances FOR EACH ROW EXECUTE FUNCTION mobile_epoch_bound_run()
    """)
    op.execute("""
        CREATE FUNCTION mobile_epoch_publication() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          IF OLD.status IS DISTINCT FROM NEW.status THEN
            INSERT INTO mobile_scope_epochs(project_id,subject_id,scope,epoch)
            SELECT DISTINCT e.project_id,e.user_id,'user',1 FROM mobile_evidence_events e
            WHERE e.project_id=NEW.project_id AND e.user_id=NEW.user_id
              AND e.harness=NEW.harness AND e.session_id=NEW.session_id
            ON CONFLICT (project_id,subject_id,scope) DO UPDATE
              SET epoch=mobile_scope_epochs.epoch+1;
            INSERT INTO mobile_scope_epochs(project_id,subject_id,scope,epoch)
            SELECT DISTINCT e.project_id,p.original_author_id,'author',1
            FROM mobile_evidence_events e JOIN mobile_listing_provenance p
              ON p.kind='mcp' AND p.listing_id=e.component_id
            WHERE e.project_id=NEW.project_id AND e.user_id=NEW.user_id
              AND e.harness=NEW.harness AND e.session_id=NEW.session_id
            ON CONFLICT (project_id,subject_id,scope) DO UPDATE
              SET epoch=mobile_scope_epochs.epoch+1;
          END IF;
          RETURN NEW;
        END $$
    """)
    op.execute("""
        CREATE TRIGGER mobile_epoch_session AFTER UPDATE OF status ON mobile_session_publications
        FOR EACH ROW EXECUTE FUNCTION mobile_epoch_publication()
    """)
    op.execute("""
        CREATE FUNCTION mobile_epoch_component_state() RETURNS trigger LANGUAGE plpgsql AS $$
        DECLARE target uuid;
        BEGIN
          target := CASE WHEN TG_OP='DELETE' THEN OLD.listing_id ELSE NEW.listing_id END;
          IF (TG_OP='DELETE' AND OLD.kind='mcp') OR (TG_OP!='DELETE' AND NEW.kind='mcp') THEN
            INSERT INTO mobile_scope_epochs(project_id,subject_id,scope,epoch)
            SELECT DISTINCT e.project_id,e.user_id,'user',1 FROM mobile_evidence_events e
            WHERE e.component_id=target
            ON CONFLICT (project_id,subject_id,scope) DO UPDATE
              SET epoch=mobile_scope_epochs.epoch+1;
            INSERT INTO mobile_scope_epochs(project_id,subject_id,scope,epoch)
            SELECT DISTINCT e.project_id,p.original_author_id,'author',1
            FROM mobile_evidence_events e JOIN mobile_listing_provenance p
              ON p.kind='mcp' AND p.listing_id=e.component_id
            WHERE e.component_id=target
            ON CONFLICT (project_id,subject_id,scope) DO UPDATE
              SET epoch=mobile_scope_epochs.epoch+1;
          END IF;
          RETURN NULL;
        END $$
    """)
    op.execute("""
        CREATE TRIGGER mobile_epoch_approval AFTER INSERT OR UPDATE OR DELETE ON mobile_publication_events
        FOR EACH ROW EXECUTE FUNCTION mobile_epoch_component_state()
    """)
    op.execute("""
        CREATE FUNCTION mobile_epoch_actor_deactivation() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          IF (OLD.auth_provider='deactivated') IS DISTINCT FROM (NEW.auth_provider='deactivated') THEN
            INSERT INTO mobile_scope_epochs(project_id,subject_id,scope,epoch)
            SELECT DISTINCT e.project_id,p.original_author_id,'author',1
            FROM mobile_evidence_events e JOIN mobile_listing_provenance p
              ON p.kind='mcp' AND p.listing_id=e.component_id
            WHERE e.user_id=NEW.id
            ON CONFLICT (project_id,subject_id,scope) DO UPDATE
              SET epoch=mobile_scope_epochs.epoch+1;
          END IF;
          RETURN NEW;
        END $$
    """)
    op.execute("""
        CREATE TRIGGER mobile_epoch_deactivation AFTER UPDATE OF auth_provider ON users
        FOR EACH ROW EXECUTE FUNCTION mobile_epoch_actor_deactivation()
    """)


def downgrade():
    for name, table in (
        ("mobile_epoch_deactivation", "users"),
        ("mobile_epoch_approval", "mobile_publication_events"),
        ("mobile_epoch_session", "mobile_session_publications"),
        ("mobile_epoch_run", "mobile_run_instances"),
        ("mobile_epoch_event_update", "mobile_evidence_events"),
        ("mobile_epoch_event_delete", "mobile_evidence_events"),
        ("mobile_epoch_event_insert", "mobile_evidence_events"),
    ):
        op.execute(f"DROP TRIGGER {name} ON {table}")
    for name in (
        "mobile_epoch_actor_deactivation",
        "mobile_epoch_component_state",
        "mobile_epoch_publication",
        "mobile_epoch_bound_run",
        "mobile_epoch_evidence_update",
        "mobile_epoch_evidence_delete",
        "mobile_epoch_evidence_insert",
    ):
        op.execute(f"DROP FUNCTION {name}()")
