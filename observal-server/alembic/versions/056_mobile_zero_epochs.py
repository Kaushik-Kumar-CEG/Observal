# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Scope cursor epochs for source-verified zero subset insertions and revocations.

Revision ID: 056_mobile_zero_epochs
Revises: 055_mobile_zero_cohort
"""

from alembic import op

revision = "056_mobile_zero_epochs"
down_revision = "055_mobile_zero_cohort"
branch_labels = None
depends_on = None


def upgrade():
    for action, relation in (("insert", "new_rows"), ("delete", "old_rows")):
        op.execute(f"""
            CREATE FUNCTION mobile_epoch_zero_{action}() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
                INSERT INTO mobile_scope_epochs(project_id,subject_id,scope,epoch)
                SELECT DISTINCT project_id,user_id,'user',1 FROM {relation}
                ON CONFLICT (project_id,subject_id,scope) DO UPDATE
                  SET epoch=mobile_scope_epochs.epoch+1;
                RETURN NULL;
            END $$
        """)
        op.execute(f"""
            CREATE TRIGGER mobile_epoch_zero_{action} AFTER {action.upper()} ON mobile_eligible_event_times
            REFERENCING {"NEW" if action == "insert" else "OLD"} TABLE AS {relation}
            FOR EACH STATEMENT EXECUTE FUNCTION mobile_epoch_zero_{action}()
        """)
    op.execute("""
        CREATE FUNCTION mobile_epoch_zero_visibility() RETURNS trigger LANGUAGE plpgsql AS $$
        DECLARE item uuid;
        BEGIN
          item := CASE WHEN TG_OP='DELETE' THEN OLD.id ELSE NEW.id END;
          INSERT INTO mobile_scope_epochs(project_id,subject_id,scope,epoch)
          SELECT DISTINCT z.project_id,z.user_id,'user',1
          FROM mobile_eligible_event_times z
          JOIN mobile_layer_components map ON map.project_id=z.project_id AND map.user_id=z.user_id
            AND map.harness=z.harness AND map.layer_hash=z.layer_hash
          WHERE map.component_id=item
          ON CONFLICT (project_id,subject_id,scope) DO UPDATE
            SET epoch=mobile_scope_epochs.epoch+1;
          RETURN NULL;
        END $$
    """)
    op.execute("""
        CREATE TRIGGER mobile_epoch_zero_listing AFTER UPDATE OF is_private OR DELETE ON mcp_listings
        FOR EACH ROW EXECUTE FUNCTION mobile_epoch_zero_visibility()
    """)
    op.execute("""
        CREATE FUNCTION mobile_epoch_zero_version() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          INSERT INTO mobile_scope_epochs(project_id,subject_id,scope,epoch)
          SELECT DISTINCT z.project_id,z.user_id,'user',1
          FROM mobile_eligible_event_times z
          JOIN mobile_layer_components map ON map.project_id=z.project_id AND map.user_id=z.user_id
            AND map.harness=z.harness AND map.layer_hash=z.layer_hash
          WHERE map.version_id=NEW.id
          ON CONFLICT (project_id,subject_id,scope) DO UPDATE
            SET epoch=mobile_scope_epochs.epoch+1;
          RETURN NULL;
        END $$
    """)
    op.execute("""
        CREATE TRIGGER mobile_epoch_zero_version AFTER UPDATE OF status ON mcp_versions
        FOR EACH ROW EXECUTE FUNCTION mobile_epoch_zero_version()
    """)
    op.execute("""
        CREATE FUNCTION mobile_epoch_zero_mapping() RETURNS trigger LANGUAGE plpgsql AS $$
        DECLARE mapped mobile_layer_components%ROWTYPE;
        BEGIN
          IF TG_OP='DELETE' THEN mapped:=OLD; ELSE mapped:=NEW; END IF;
          INSERT INTO mobile_scope_epochs(project_id,subject_id,scope,epoch)
          SELECT DISTINCT z.project_id,z.user_id,'user',1 FROM mobile_eligible_event_times z
          WHERE z.project_id=mapped.project_id
            AND z.user_id=mapped.user_id
            AND z.harness=mapped.harness
            AND z.layer_hash=mapped.layer_hash
          ON CONFLICT (project_id,subject_id,scope) DO UPDATE
            SET epoch=mobile_scope_epochs.epoch+1;
          RETURN NULL;
        END $$
    """)
    op.execute("""
        CREATE TRIGGER mobile_epoch_zero_map AFTER INSERT OR UPDATE OR DELETE ON mobile_layer_components
        FOR EACH ROW EXECUTE FUNCTION mobile_epoch_zero_mapping()
    """)
    op.execute("""
        CREATE FUNCTION mobile_epoch_zero_approval() RETURNS trigger LANGUAGE plpgsql AS $$
        DECLARE publication mobile_publication_events%ROWTYPE;
        BEGIN
          IF TG_OP='DELETE' THEN publication:=OLD; ELSE publication:=NEW; END IF;
          IF publication.kind='mcp' THEN
            INSERT INTO mobile_scope_epochs(project_id,subject_id,scope,epoch)
            SELECT DISTINCT z.project_id,z.user_id,'user',1 FROM mobile_eligible_event_times z
            JOIN mobile_layer_components map ON map.project_id=z.project_id AND map.user_id=z.user_id
              AND map.harness=z.harness AND map.layer_hash=z.layer_hash
            WHERE map.component_id=publication.listing_id
            ON CONFLICT (project_id,subject_id,scope) DO UPDATE
              SET epoch=mobile_scope_epochs.epoch+1;
          END IF;
          RETURN NULL;
        END $$
    """)
    op.execute("""
        CREATE TRIGGER mobile_epoch_zero_approval AFTER INSERT OR UPDATE OR DELETE ON mobile_publication_events
        FOR EACH ROW EXECUTE FUNCTION mobile_epoch_zero_approval()
    """)
    op.execute("""
        CREATE FUNCTION mobile_epoch_zero_pub() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          IF OLD.status IS DISTINCT FROM NEW.status OR OLD.source_revision IS DISTINCT FROM NEW.source_revision THEN
            INSERT INTO mobile_scope_epochs(project_id,subject_id,scope,epoch)
            SELECT DISTINCT z.project_id,z.user_id,'user',1 FROM mobile_eligible_event_times z
            WHERE z.project_id=NEW.project_id AND z.user_id=NEW.user_id
              AND z.harness=NEW.harness AND z.session_id=NEW.session_id
            ON CONFLICT (project_id,subject_id,scope) DO UPDATE
              SET epoch=mobile_scope_epochs.epoch+1;
          END IF;
          RETURN NEW;
        END $$
    """)
    op.execute("""
        CREATE TRIGGER mobile_epoch_zero_publication AFTER UPDATE OF status,source_revision
        ON mobile_session_publications FOR EACH ROW EXECUTE FUNCTION mobile_epoch_zero_pub()
    """)
    op.execute("""
        CREATE FUNCTION mobile_epoch_zero_run() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          IF OLD.root_verified IS DISTINCT FROM NEW.root_verified THEN
            INSERT INTO mobile_scope_epochs(project_id,subject_id,scope,epoch)
            SELECT DISTINCT z.project_id,z.user_id,'user',1 FROM mobile_eligible_event_times z
            WHERE z.project_id=NEW.project_id AND z.user_id=NEW.user_id
              AND z.harness=NEW.harness AND z.session_id=NEW.session_id
            ON CONFLICT (project_id,subject_id,scope) DO UPDATE
              SET epoch=mobile_scope_epochs.epoch+1;
          END IF;
          RETURN NEW;
        END $$
    """)
    op.execute("""
        CREATE TRIGGER mobile_epoch_zero_root AFTER UPDATE OF root_verified ON mobile_run_instances
        FOR EACH ROW EXECUTE FUNCTION mobile_epoch_zero_run()
    """)


def downgrade():
    for name, table in (
        ("mobile_epoch_zero_approval", "mobile_publication_events"),
        ("mobile_epoch_zero_map", "mobile_layer_components"),
        ("mobile_epoch_zero_root", "mobile_run_instances"),
        ("mobile_epoch_zero_publication", "mobile_session_publications"),
        ("mobile_epoch_zero_version", "mcp_versions"),
        ("mobile_epoch_zero_listing", "mcp_listings"),
        ("mobile_epoch_zero_delete", "mobile_eligible_event_times"),
        ("mobile_epoch_zero_insert", "mobile_eligible_event_times"),
    ):
        op.execute(f"DROP TRIGGER {name} ON {table}")
    for name in (
        "mobile_epoch_zero_approval",
        "mobile_epoch_zero_mapping",
        "mobile_epoch_zero_run",
        "mobile_epoch_zero_pub",
        "mobile_epoch_zero_version",
        "mobile_epoch_zero_visibility",
        "mobile_epoch_zero_delete",
        "mobile_epoch_zero_insert",
    ):
        op.execute(f"DROP FUNCTION {name}()")
