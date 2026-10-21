# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Add dormant, owner-isolated follow-sync 1.0.5 storage. No endpoints or policy enabled.

All admission counters are guarded by CHECKs but must be reserved under a locked
partition row by a future service. Retention/erasure workers and revocation are
likewise NOT implemented by this migration.

Revision ID: 070_mobile_follow_sync_state
Revises: 069_mobile_publication_clock
"""

from alembic import op

revision = "070_mobile_follow_sync_state"
down_revision = "069_mobile_publication_clock"
branch_labels = None
depends_on = None

# Every child carries the complete partition key. Never reference an operation,
# lease or receipt by its UUID alone. Owner deletion cascades through this root.
KEY = "server_id uuid NOT NULL, project_id varchar(256) NOT NULL, owner_id uuid NOT NULL, cohort varchar(64) NOT NULL"
PK = "server_id, project_id, owner_id, cohort"
PARENT = f"FOREIGN KEY ({PK}) REFERENCES mobile_follow_partitions ({PK}) ON DELETE CASCADE"
SAFE = "9007199254740991"


def upgrade():
    op.execute(f"""
        CREATE TABLE mobile_follow_partitions (
            {KEY}, owner_generation bigint NOT NULL DEFAULT 1,
            current_revision bigint NOT NULL DEFAULT 0,
            erasure_floor bigint NOT NULL DEFAULT 0,
            consent_state varchar(24) NOT NULL DEFAULT 'consent_required',
            removal_state varchar(24) NOT NULL DEFAULT 'none',
            subject_count integer NOT NULL DEFAULT 0,
            normal_outcomes integer NOT NULL DEFAULT 0,
            reserved_outcomes integer NOT NULL DEFAULT 0,
            history_bytes integer NOT NULL DEFAULT 0,
            pin_bytes integer NOT NULL DEFAULT 0,
            consent_bindings integer NOT NULL DEFAULT 0,
            indexed_receipts integer NOT NULL DEFAULT 0,
            updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
            PRIMARY KEY ({PK}),
            FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE,
            CHECK (owner_generation BETWEEN 1 AND {SAFE}),
            CHECK (current_revision BETWEEN 0 AND {SAFE}),
            CHECK (erasure_floor BETWEEN 0 AND {SAFE}),
            CHECK (consent_state IN ('consent_required','available','withdrawal_pending','restricted','disabled')),
            CHECK (removal_state IN ('none','pending','needs_operator')),
            CHECK (subject_count BETWEEN 0 AND 1000),
            CHECK (normal_outcomes BETWEEN 0 AND 10000),
            CHECK (reserved_outcomes BETWEEN 0 AND 1000),
            CHECK (history_bytes BETWEEN 0 AND 16777216),
            CHECK (pin_bytes BETWEEN 0 AND 2097152),
            CHECK (consent_bindings BETWEEN 0 AND 1000),
            CHECK (indexed_receipts BETWEEN 0 AND 1000)
        )
    """)
    op.execute(f"""
        CREATE TABLE mobile_follow_subjects (
            {KEY}, subject_id uuid NOT NULL, person_revision bigint NOT NULL,
            following boolean NOT NULL, changed_revision bigint NOT NULL,
            PRIMARY KEY ({PK}, subject_id), {PARENT},
            FOREIGN KEY (subject_id) REFERENCES users(id) ON DELETE CASCADE,
            CHECK (person_revision BETWEEN 1 AND {SAFE}),
            CHECK (changed_revision BETWEEN 1 AND {SAFE})
        )
    """)
    op.execute(f"""
        CREATE TABLE mobile_follow_operations (
            {KEY}, operation_id uuid NOT NULL, original_generation bigint NOT NULL,
            subject_id uuid, body_digest bytea, original_http_status smallint NOT NULL,
            outcome jsonb, effective boolean NOT NULL DEFAULT true,
            lane varchar(8) NOT NULL, logical_bytes integer NOT NULL,
            admitted_at timestamptz NOT NULL DEFAULT clock_timestamp(), expires_at timestamptz NOT NULL,
            PRIMARY KEY ({PK}, operation_id), {PARENT},
            FOREIGN KEY (subject_id) REFERENCES users(id) ON DELETE SET NULL (subject_id),
            CHECK (original_generation BETWEEN 1 AND {SAFE}),
            CHECK (original_http_status IN (200,409)),
            CHECK (lane IN ('normal','reserved')),
            CHECK (logical_bytes BETWEEN 1 AND 4096),
            CHECK (expires_at >= admitted_at + interval '90 days'),
            CHECK ((effective AND subject_id IS NOT NULL AND body_digest IS NOT NULL AND outcome IS NOT NULL)
                OR (NOT effective AND subject_id IS NULL AND body_digest IS NULL AND outcome IS NULL)),
            CHECK (body_digest IS NULL OR octet_length(body_digest)=32),
            CHECK (outcome IS NULL OR octet_length(outcome::text) <= 4096)
        )
    """)
    op.execute(f"CREATE INDEX ix_mobile_follow_operations_expiry ON mobile_follow_operations (expires_at, {PK})")
    op.execute(f"""
        CREATE TABLE mobile_follow_changes (
            {KEY}, owner_generation bigint NOT NULL, revision bigint NOT NULL,
            ordinal integer NOT NULL, subject_id uuid NOT NULL, person_revision bigint NOT NULL,
            following boolean NOT NULL, admitted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
            expires_at timestamptz NOT NULL, logical_bytes integer NOT NULL,
            PRIMARY KEY ({PK}, owner_generation, revision, ordinal), {PARENT},
            FOREIGN KEY (subject_id) REFERENCES users(id) ON DELETE CASCADE,
            CHECK (owner_generation BETWEEN 1 AND {SAFE}),
            CHECK (revision BETWEEN 1 AND {SAFE}),
            CHECK (ordinal BETWEEN 0 AND 1000),
            CHECK (person_revision BETWEEN 1 AND {SAFE}),
            CHECK (logical_bytes BETWEEN 1 AND 512),
            CHECK (expires_at >= admitted_at + interval '90 days')
        )
    """)
    op.execute(f"CREATE INDEX ix_mobile_follow_changes_expiry ON mobile_follow_changes (expires_at, {PK})")
    op.execute(f"""
        CREATE TABLE mobile_follow_leases (
            {KEY}, lease_id uuid NOT NULL, kind varchar(8) NOT NULL,
            slot smallint NOT NULL, device_id varchar(128), owner_generation bigint NOT NULL,
            pinned_revision bigint NOT NULL, erasure_floor bigint NOT NULL,
            after_revision bigint, upper_revision bigint,
            logical_bytes integer NOT NULL, row_count integer NOT NULL,
            admitted_at timestamptz NOT NULL DEFAULT clock_timestamp(), expires_at timestamptz NOT NULL,
            PRIMARY KEY ({PK}, lease_id), UNIQUE ({PK}, kind, slot), {PARENT},
            CHECK (kind IN ('image','changes')),
            CHECK (slot IN (1,2)),
            CHECK (owner_generation BETWEEN 1 AND {SAFE}),
            CHECK (pinned_revision BETWEEN 0 AND {SAFE}),
            CHECK (erasure_floor BETWEEN 0 AND {SAFE}),
            CHECK (logical_bytes BETWEEN 0 AND 2097152),
            CHECK (row_count BETWEEN 0 AND 1000),
            CHECK (expires_at = admitted_at + interval '15 minutes'),
            CHECK ((kind='image' AND after_revision IS NULL AND upper_revision IS NULL AND device_id IS NULL)
                OR (kind='changes' AND device_id IS NOT NULL AND after_revision BETWEEN 0 AND {SAFE}
                    AND upper_revision BETWEEN after_revision AND {SAFE}))
        )
    """)
    op.execute(f"CREATE INDEX ix_mobile_follow_leases_expiry ON mobile_follow_leases (expires_at, {PK})")
    op.execute(
        f"CREATE UNIQUE INDEX uq_mobile_follow_change_device ON mobile_follow_leases ({PK}, device_id) WHERE kind='changes'"
    )
    op.execute(f"""
        CREATE TABLE mobile_follow_pins (
            {KEY}, lease_id uuid NOT NULL, row_number integer NOT NULL,
            subject_id uuid, person_revision bigint, following boolean,
            revision bigint, ordinal integer, logical_bytes integer NOT NULL,
            PRIMARY KEY ({PK}, lease_id, row_number),
            FOREIGN KEY ({PK}, lease_id) REFERENCES mobile_follow_leases ({PK}, lease_id) ON DELETE CASCADE,
            FOREIGN KEY (subject_id) REFERENCES users(id) ON DELETE CASCADE,
            CHECK (row_number BETWEEN 1 AND 1000),
            CHECK (logical_bytes BETWEEN 1 AND 512),
            CHECK (person_revision IS NULL OR person_revision BETWEEN 1 AND {SAFE}),
            CHECK (revision IS NULL OR revision BETWEEN 1 AND {SAFE}),
            CHECK (ordinal IS NULL OR ordinal BETWEEN 0 AND 1000)
        )
    """)
    op.execute(f"""
        CREATE TABLE mobile_follow_page_throttles (
            {KEY}, lease_id uuid NOT NULL, page_key integer NOT NULL,
            rate_limited boolean NOT NULL DEFAULT false,
            PRIMARY KEY ({PK}, lease_id, page_key),
            FOREIGN KEY ({PK}, lease_id) REFERENCES mobile_follow_leases ({PK}, lease_id) ON DELETE CASCADE,
            CHECK (page_key BETWEEN 0 AND 10)
        )
    """)
    op.execute(f"""
        CREATE TABLE mobile_follow_approvals (
            {KEY}, device_id varchar(128) NOT NULL, challenge_digest bytea NOT NULL,
            owner_generation bigint NOT NULL, status varchar(12) NOT NULL DEFAULT 'pending',
            issued_at timestamptz NOT NULL DEFAULT clock_timestamp(),
            expires_at timestamptz NOT NULL, approved_at timestamptz,
            PRIMARY KEY ({PK}, device_id), UNIQUE ({PK}, challenge_digest), {PARENT},
            CHECK (octet_length(challenge_digest)=32),
            CHECK (owner_generation BETWEEN 1 AND {SAFE}),
            CHECK (status IN ('pending','approved','denied','revoked')),
            CHECK (expires_at <= issued_at + interval '600 seconds'),
            CHECK ((status='approved') = (approved_at IS NOT NULL))
        )
    """)
    op.execute(f"CREATE INDEX ix_mobile_follow_approvals_expiry ON mobile_follow_approvals (expires_at, {PK})")
    op.execute(f"""
        CREATE TABLE mobile_follow_consents (
            {KEY}, consent_id uuid NOT NULL, request_generation bigint NOT NULL,
            accepted_generation bigint NOT NULL, body_digest bytea NOT NULL,
            accepted_at timestamptz NOT NULL DEFAULT clock_timestamp(), expires_at timestamptz NOT NULL,
            PRIMARY KEY ({PK}, consent_id), {PARENT},
            CHECK (request_generation BETWEEN 1 AND {SAFE}),
            CHECK (accepted_generation = request_generation + 1),
            CHECK (octet_length(body_digest)=32),
            CHECK (expires_at >= accepted_at + interval '90 days')
        )
    """)
    op.execute(f"CREATE INDEX ix_mobile_follow_consents_expiry ON mobile_follow_consents (expires_at, {PK})")
    op.execute(f"""
        CREATE TABLE mobile_follow_nonces (
            {KEY}, device_id varchar(128) NOT NULL, nonce_digest bytea NOT NULL,
            owner_generation bigint NOT NULL,
            issued_at timestamptz NOT NULL DEFAULT clock_timestamp(), expires_at timestamptz NOT NULL,
            PRIMARY KEY ({PK}, device_id), UNIQUE ({PK}, nonce_digest), {PARENT},
            CHECK (octet_length(nonce_digest)=32),
            CHECK (owner_generation BETWEEN 1 AND {SAFE}),
            CHECK (expires_at <= issued_at + interval '120 seconds')
        )
    """)
    op.execute(f"""
        CREATE TABLE mobile_follow_privacy_actions (
            {KEY}, action_id uuid NOT NULL, kind varchar(12) NOT NULL,
            recovery_mode varchar(16) NOT NULL,
            device_id varchar(128), nonce_digest bytea, body_digest bytea,
            original_generation bigint NOT NULL, fenced_generation bigint NOT NULL,
            status varchar(16) NOT NULL DEFAULT 'pending',
            worker_cursor uuid, logical_bytes integer NOT NULL DEFAULT 0,
            admitted_at timestamptz NOT NULL DEFAULT clock_timestamp(), expires_at timestamptz,
            PRIMARY KEY ({PK}, action_id), {PARENT},
            CHECK (kind IN ('removal','withdrawal')),
            CHECK (recovery_mode IN ('nonce_lookup_90d','state_only')),
            CHECK (status IN ('pending','needs_operator','completed')),
            CHECK (original_generation BETWEEN 1 AND {SAFE}),
            CHECK (fenced_generation = original_generation + 1),
            CHECK (nonce_digest IS NULL OR octet_length(nonce_digest)=32),
            CHECK (logical_bytes BETWEEN 0 AND 4096),
            CHECK ((kind='removal' AND nonce_digest IS NOT NULL AND device_id IS NOT NULL AND body_digest IS NULL)
                OR (kind='withdrawal' AND nonce_digest IS NULL AND body_digest IS NOT NULL
                    AND octet_length(body_digest)=32)),
            CHECK ((recovery_mode='state_only' AND expires_at IS NULL)
                OR (recovery_mode='nonce_lookup_90d' AND expires_at IS NOT NULL
                    AND expires_at >= admitted_at + interval '90 days'))
        )
    """)
    op.execute(
        f"CREATE UNIQUE INDEX uq_mobile_follow_current_recovery ON mobile_follow_privacy_actions ({PK}) WHERE recovery_mode='state_only'"
    )
    op.execute(
        f"CREATE UNIQUE INDEX uq_mobile_follow_nonce_lookup ON mobile_follow_privacy_actions ({PK}, device_id, nonce_digest) WHERE nonce_digest IS NOT NULL"
    )
    op.execute(
        f"CREATE INDEX ix_mobile_follow_privacy_expiry ON mobile_follow_privacy_actions (expires_at, {PK}) WHERE expires_at IS NOT NULL"
    )
    # Subject DSR must redact outcome before the subject FK runs (SET NULL
    # alone would violate the effective-result check). Invalidate *all* pinned
    # pages for affected partitions, including change leases without an image.
    op.execute("""
        CREATE FUNCTION mobile_follow_erase_subject() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            UPDATE mobile_follow_partitions p SET erasure_floor=erasure_floor+1,
                subject_count=subject_count - CASE WHEN EXISTS (
                    SELECT 1 FROM mobile_follow_subjects s WHERE s.server_id=p.server_id
                    AND s.project_id=p.project_id AND s.owner_id=p.owner_id
                    AND s.cohort=p.cohort AND s.subject_id=OLD.id) THEN 1 ELSE 0 END,
                pin_bytes=0, updated_at=clock_timestamp()
              WHERE EXISTS (SELECT 1 FROM mobile_follow_subjects s WHERE s.server_id=p.server_id
                    AND s.project_id=p.project_id AND s.owner_id=p.owner_id
                    AND s.cohort=p.cohort AND s.subject_id=OLD.id)
                 OR EXISTS (SELECT 1 FROM mobile_follow_changes c WHERE c.server_id=p.server_id
                    AND c.project_id=p.project_id AND c.owner_id=p.owner_id
                    AND c.cohort=p.cohort AND c.subject_id=OLD.id)
                 OR EXISTS (SELECT 1 FROM mobile_follow_operations o WHERE o.server_id=p.server_id
                    AND o.project_id=p.project_id AND o.owner_id=p.owner_id
                    AND o.cohort=p.cohort AND o.subject_id=OLD.id)
                 OR EXISTS (SELECT 1 FROM mobile_follow_pins i WHERE i.server_id=p.server_id
                    AND i.project_id=p.project_id AND i.owner_id=p.owner_id
                    AND i.cohort=p.cohort AND i.subject_id=OLD.id);
            UPDATE mobile_follow_operations SET subject_id=NULL, body_digest=NULL,
                outcome=NULL, effective=false WHERE subject_id=OLD.id;
            DELETE FROM mobile_follow_leases l USING mobile_follow_partitions p
                WHERE l.server_id=p.server_id AND l.project_id=p.project_id
                  AND l.owner_id=p.owner_id AND l.cohort=p.cohort
                  AND (EXISTS (SELECT 1 FROM mobile_follow_subjects s
                      WHERE s.server_id=p.server_id AND s.project_id=p.project_id
                        AND s.owner_id=p.owner_id AND s.cohort=p.cohort AND s.subject_id=OLD.id)
                    OR EXISTS (SELECT 1 FROM mobile_follow_changes c
                      WHERE c.server_id=p.server_id AND c.project_id=p.project_id
                        AND c.owner_id=p.owner_id AND c.cohort=p.cohort AND c.subject_id=OLD.id)
                    OR EXISTS (SELECT 1 FROM mobile_follow_pins i
                      WHERE i.server_id=p.server_id AND i.project_id=p.project_id
                        AND i.owner_id=p.owner_id AND i.cohort=p.cohort AND i.subject_id=OLD.id));
            DELETE FROM mobile_follow_changes WHERE subject_id=OLD.id;
            DELETE FROM mobile_follow_subjects WHERE subject_id=OLD.id;
            RETURN OLD;
        END $$
    """)
    op.execute("""
        CREATE TRIGGER mobile_follow_erase_subject BEFORE DELETE ON users
        FOR EACH ROW EXECUTE FUNCTION mobile_follow_erase_subject()
    """)


def downgrade():
    raise RuntimeError(
        "Cannot discard follow-sync consent, privacy receipts or erasure fences; restore an isolated backup"
    )
