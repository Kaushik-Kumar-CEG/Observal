# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Prospective, deletion-safe mobile original author and publication transitions.

Revision ID: 045_mobile_provenance
Revises: 044_review_orphan_authors
"""

import uuid

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

from alembic import op

revision = "045_mobile_provenance"
down_revision = "044_review_orphan_authors"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "mobile_server_identity",
        sa.Column("singleton", sa.Boolean(), primary_key=True),
        sa.Column("server_id", UUID(as_uuid=True), nullable=False),
        sa.CheckConstraint("singleton", name="ck_mobile_server_identity_singleton"),
    )
    op.execute(
        sa.text("INSERT INTO mobile_server_identity (singleton, server_id) VALUES (true, :id)").bindparams(
            sa.bindparam("id", uuid.uuid4(), type_=UUID(as_uuid=True))
        )
    )
    op.create_table(
        "mobile_listing_provenance",
        sa.Column("kind", sa.String(16), primary_key=True),
        sa.Column("listing_id", UUID(as_uuid=True), primary_key=True),
        # No FK: deleting a user must never block deletion. Reads require a live User.
        sa.Column("original_author_id", UUID(as_uuid=True), nullable=False),
        sa.Column("captured_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_mobile_provenance_author", "mobile_listing_provenance", ["original_author_id", "kind"])
    op.create_table(
        "mobile_publication_events",
        sa.Column("id", sa.BigInteger(), sa.Identity(), primary_key=True),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("listing_id", UUID(as_uuid=True), nullable=False),
        sa.Column("version_id", UUID(as_uuid=True), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index(
        "ix_mobile_publication_event_time",
        "mobile_publication_events",
        ["kind", "listing_id", "recorded_at", "id"],
    )
    op.create_table(
        "mobile_verified_layers",
        sa.Column("project_id", sa.String(64), primary_key=True),
        sa.Column("user_id", UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("harness", sa.String(32), primary_key=True),
        sa.Column("layer_hash", sa.String(67), primary_key=True),
        sa.Column("expected_components", sa.SmallInteger(), nullable=False),
        sa.Column("uploaded_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_table(
        "mobile_layer_components",
        sa.Column("project_id", sa.String(64), primary_key=True),
        sa.Column("user_id", UUID(as_uuid=True), primary_key=True),
        sa.Column("harness", sa.String(32), primary_key=True),
        sa.Column("layer_hash", sa.String(67), primary_key=True),
        sa.Column("alias", sa.String(128), primary_key=True),
        sa.Column(
            "component_id", UUID(as_uuid=True), sa.ForeignKey("mcp_listings.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column(
            "version_id", UUID(as_uuid=True), sa.ForeignKey("mcp_versions.id", ondelete="CASCADE"), nullable=False
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
        "mobile_evidence_events",
        sa.Column("project_id", sa.String(64), primary_key=True),
        sa.Column("user_id", UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("harness", sa.String(32), primary_key=True),
        sa.Column("session_id", sa.String(256), primary_key=True),
        sa.Column("source_line_offset", sa.Integer(), primary_key=True),
        sa.Column("block_key", sa.String(270), primary_key=True),
        sa.Column("layer_hash", sa.String(67), nullable=False),
        sa.Column("alias", sa.String(128), nullable=False),
        sa.Column(
            "component_id", UUID(as_uuid=True), sa.ForeignKey("mcp_listings.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("root_session_id", sa.String(256), nullable=True),
        sa.Column("event_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("result_state", sa.String(16), nullable=False),
        sa.ForeignKeyConstraint(
            ["project_id", "user_id", "harness", "layer_hash", "alias"],
            [
                "mobile_layer_components.project_id",
                "mobile_layer_components.user_id",
                "mobile_layer_components.harness",
                "mobile_layer_components.layer_hash",
                "mobile_layer_components.alias",
            ],
            ondelete="CASCADE",
        ),
    )
    op.create_index("ix_mobile_evidence_user_time", "mobile_evidence_events", ["user_id", "event_time"])
    op.create_index("ix_mobile_evidence_component_time", "mobile_evidence_events", ["component_id", "event_time"])
    op.create_table(
        "mobile_session_publications",
        sa.Column("project_id", sa.String(64), primary_key=True),
        sa.Column("user_id", UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("harness", sa.String(32), primary_key=True),
        sa.Column("session_id", sa.String(256), primary_key=True),
        sa.Column("source_revision", sa.String(64), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_mobile_publication_status", "mobile_session_publications", ["status", "updated_at"])
    op.create_table(
        "mobile_projection_queue",
        sa.Column("project_id", sa.String(64), primary_key=True),
        sa.Column("user_id", UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("harness", sa.String(32), primary_key=True),
        sa.Column("session_id", sa.String(256), primary_key=True),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
    )
    op.create_index("ix_mobile_queue_oldest", "mobile_projection_queue", ["requested_at"])
    # Install before new writes. Deliberately do NOT backfill past owners/approvals:
    # submitted_by and created_by change on transfer, and old approved versions
    # have no provable event-time transition.
    op.execute("""
        CREATE FUNCTION mobile_record_author() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            INSERT INTO mobile_listing_provenance(kind, listing_id, original_author_id)
            VALUES (TG_ARGV[0], NEW.id,
                COALESCE(to_jsonb(NEW)->>'created_by', to_jsonb(NEW)->>'submitted_by')::uuid)
            ON CONFLICT DO NOTHING;
            RETURN NEW;
        END $$
    """)
    op.execute("""
        CREATE FUNCTION mobile_record_publication() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF TG_OP = 'INSERT' OR NEW.status IS DISTINCT FROM OLD.status THEN
                INSERT INTO mobile_publication_events(kind, listing_id, version_id, status)
                VALUES (TG_ARGV[0], NEW."listing_id", NEW.id, NEW.status::text);
            END IF;
            RETURN NEW;
        END $$
    """)
    # Deletion must not retain a mobile-specific named author marker. Source
    # telemetry erasure is governed separately by the deployment policy.
    op.execute("""
        CREATE FUNCTION mobile_erase_user_provenance() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            WITH removed AS (
                DELETE FROM mobile_listing_provenance WHERE original_author_id = OLD.id
                RETURNING kind, listing_id
            )
            DELETE FROM mobile_publication_events e USING removed r
            WHERE e.kind = r.kind AND e.listing_id = r.listing_id;
            RETURN OLD;
        END $$
    """)
    op.execute(
        "CREATE TRIGGER mobile_erase_user BEFORE DELETE ON users FOR EACH ROW EXECUTE FUNCTION mobile_erase_user_provenance()"
    )
    op.execute("""
        CREATE FUNCTION mobile_erase_listing_provenance() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            DELETE FROM mobile_listing_provenance WHERE kind = TG_ARGV[0] AND listing_id = OLD.id;
            DELETE FROM mobile_publication_events WHERE kind = TG_ARGV[0] AND listing_id = OLD.id;
            IF TG_ARGV[0] = 'mcp' THEN
                DELETE FROM mobile_evidence_events WHERE component_id = OLD.id;
            END IF;
            RETURN OLD;
        END $$
    """)
    # Agent versions refer to agent_id rather than listing_id.
    op.execute("""
        CREATE FUNCTION mobile_record_agent_publication() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF TG_OP = 'INSERT' OR NEW.status IS DISTINCT FROM OLD.status THEN
                INSERT INTO mobile_publication_events(kind, listing_id, version_id, status)
                VALUES ('agent', NEW.agent_id, NEW.id, NEW.status::text);
            END IF;
            RETURN NEW;
        END $$
    """)
    for kind, table in (
        ("mcp", "mcp_listings"),
        ("skill", "skill_listings"),
        ("hook", "hook_listings"),
        ("prompt", "prompt_listings"),
        ("sandbox", "sandbox_listings"),
        ("agent", "agents"),
    ):
        op.execute(
            f"CREATE TRIGGER mobile_author_{kind} AFTER INSERT ON {table} FOR EACH ROW EXECUTE FUNCTION mobile_record_author('{kind}')"
        )
        op.execute(
            f"CREATE TRIGGER mobile_erase_listing_{kind} AFTER DELETE ON {table} "
            f"FOR EACH ROW EXECUTE FUNCTION mobile_erase_listing_provenance('{kind}')"
        )
    for kind, table in (
        ("mcp", "mcp_versions"),
        ("skill", "skill_versions"),
        ("hook", "hook_versions"),
        ("prompt", "prompt_versions"),
        ("sandbox", "sandbox_versions"),
    ):
        op.execute(
            f"CREATE TRIGGER mobile_publication_{kind} AFTER INSERT OR UPDATE OF status ON {table} "
            f"FOR EACH ROW EXECUTE FUNCTION mobile_record_publication('{kind}')"
        )
    op.execute(
        "CREATE TRIGGER mobile_publication_agent AFTER INSERT OR UPDATE OF status ON agent_versions "
        "FOR EACH ROW EXECUTE FUNCTION mobile_record_agent_publication()"
    )


def downgrade():
    op.execute("DROP TRIGGER mobile_erase_user ON users")
    for kind in ("mcp", "skill", "hook", "prompt", "sandbox", "agent"):
        op.execute(f"DROP TRIGGER mobile_author_{kind} ON {'agents' if kind == 'agent' else kind + '_listings'}")
        op.execute(f"DROP TRIGGER mobile_erase_listing_{kind} ON {'agents' if kind == 'agent' else kind + '_listings'}")
        op.execute(
            f"DROP TRIGGER mobile_publication_{kind} ON {'agent_versions' if kind == 'agent' else kind + '_versions'}"
        )
    op.execute("DROP FUNCTION mobile_erase_listing_provenance()")
    op.execute("DROP FUNCTION mobile_erase_user_provenance()")
    op.execute("DROP FUNCTION mobile_record_agent_publication()")
    op.execute("DROP FUNCTION mobile_record_publication()")
    op.execute("DROP FUNCTION mobile_record_author()")
    op.drop_table("mobile_projection_queue")
    op.drop_table("mobile_session_publications")
    op.drop_table("mobile_evidence_events")
    op.drop_table("mobile_layer_components")
    op.drop_table("mobile_verified_layers")
    op.drop_table("mobile_publication_events")
    op.drop_table("mobile_listing_provenance")
    op.drop_table("mobile_server_identity")
