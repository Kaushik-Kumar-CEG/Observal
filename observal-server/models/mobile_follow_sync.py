# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Dormant 1.0.5 follow-sync persistence mappings; no API/authorization policy."""

import uuid
from datetime import datetime

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    LargeBinary,
    SmallInteger,
    String,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from models.base import Base

KEY = ("server_id", "project_id", "owner_id", "cohort")


def parent_fk():
    return ForeignKeyConstraint(KEY, [f"mobile_follow_partitions.{k}" for k in KEY], ondelete="CASCADE")


SAFE = 9007199254740991


class PartitionKey:
    server_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    project_id: Mapped[str] = mapped_column(String(256), primary_key=True)
    owner_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    cohort: Mapped[str] = mapped_column(String(64), primary_key=True)


class MobileFollowPartition(PartitionKey, Base):
    __tablename__ = "mobile_follow_partitions"
    __table_args__ = (
        CheckConstraint(f"owner_generation BETWEEN 1 AND {SAFE}"),
        CheckConstraint(f"current_revision BETWEEN 0 AND {SAFE}"),
        CheckConstraint(f"erasure_floor BETWEEN 0 AND {SAFE}"),
        CheckConstraint("subject_count BETWEEN 0 AND 1000"),
        CheckConstraint("normal_outcomes BETWEEN 0 AND 10000"),
        CheckConstraint("reserved_outcomes BETWEEN 0 AND 1000"),
        CheckConstraint("history_bytes BETWEEN 0 AND 16777216"),
        CheckConstraint("pin_bytes BETWEEN 0 AND 2097152"),
        CheckConstraint("consent_bindings BETWEEN 0 AND 1000"),
        CheckConstraint("indexed_receipts BETWEEN 0 AND 1000"),
    )
    # FK placed on the sole root, not independently on each child.
    owner_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    owner_generation: Mapped[int] = mapped_column(BigInteger, server_default="1")
    current_revision: Mapped[int] = mapped_column(BigInteger, server_default="0")
    erasure_floor: Mapped[int] = mapped_column(BigInteger, server_default="0")
    consent_state: Mapped[str] = mapped_column(String(24), server_default="consent_required")
    removal_state: Mapped[str] = mapped_column(String(24), server_default="none")
    subject_count: Mapped[int] = mapped_column(Integer, server_default="0")
    normal_outcomes: Mapped[int] = mapped_column(Integer, server_default="0")
    reserved_outcomes: Mapped[int] = mapped_column(Integer, server_default="0")
    history_bytes: Mapped[int] = mapped_column(Integer, server_default="0")
    pin_bytes: Mapped[int] = mapped_column(Integer, server_default="0")
    consent_bindings: Mapped[int] = mapped_column(Integer, server_default="0")
    indexed_receipts: Mapped[int] = mapped_column(Integer, server_default="0")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("clock_timestamp()"))


class MobileFollowSubject(PartitionKey, Base):
    __tablename__ = "mobile_follow_subjects"
    __table_args__ = (parent_fk(),)
    subject_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    person_revision: Mapped[int] = mapped_column(BigInteger)
    following: Mapped[bool] = mapped_column(Boolean)
    changed_revision: Mapped[int] = mapped_column(BigInteger)


class MobileFollowOperation(PartitionKey, Base):
    __tablename__ = "mobile_follow_operations"
    __table_args__ = (parent_fk(), Index("ix_mobile_follow_operations_expiry", "expires_at", *KEY))
    operation_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    original_generation: Mapped[int] = mapped_column(BigInteger)
    subject_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    body_digest: Mapped[bytes | None] = mapped_column(LargeBinary)
    original_http_status: Mapped[int] = mapped_column(SmallInteger)
    outcome: Mapped[dict | None] = mapped_column(JSONB().with_variant(JSON(), "sqlite"))
    effective: Mapped[bool] = mapped_column(Boolean, server_default="true")
    lane: Mapped[str] = mapped_column(String(8))
    logical_bytes: Mapped[int] = mapped_column(Integer)
    admitted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("clock_timestamp()"))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class MobileFollowChange(PartitionKey, Base):
    __tablename__ = "mobile_follow_changes"
    __table_args__ = (parent_fk(), Index("ix_mobile_follow_changes_expiry", "expires_at", *KEY))
    owner_generation: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    revision: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    ordinal: Mapped[int] = mapped_column(Integer, primary_key=True)
    subject_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"))
    person_revision: Mapped[int] = mapped_column(BigInteger)
    following: Mapped[bool] = mapped_column(Boolean)
    admitted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("clock_timestamp()"))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    logical_bytes: Mapped[int] = mapped_column(Integer)


class MobileFollowLease(PartitionKey, Base):
    __tablename__ = "mobile_follow_leases"
    __table_args__ = (
        parent_fk(),
        UniqueConstraint(*KEY, "kind", "slot"),
        Index("ix_mobile_follow_leases_expiry", "expires_at", *KEY),
        Index(
            "uq_mobile_follow_change_device", *KEY, "device_id", unique=True, postgresql_where=text("kind='changes'")
        ),
    )
    lease_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    kind: Mapped[str] = mapped_column(String(8))
    slot: Mapped[int] = mapped_column(SmallInteger)
    device_id: Mapped[str | None] = mapped_column(String(128))
    owner_generation: Mapped[int] = mapped_column(BigInteger)
    pinned_revision: Mapped[int] = mapped_column(BigInteger)
    erasure_floor: Mapped[int] = mapped_column(BigInteger)
    after_revision: Mapped[int | None] = mapped_column(BigInteger)
    upper_revision: Mapped[int | None] = mapped_column(BigInteger)
    logical_bytes: Mapped[int] = mapped_column(Integer)
    row_count: Mapped[int] = mapped_column(Integer)
    admitted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("clock_timestamp()"))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


def lease_fk():
    return ForeignKeyConstraint(
        (*KEY, "lease_id"), [f"mobile_follow_leases.{k}" for k in (*KEY, "lease_id")], ondelete="CASCADE"
    )


class MobileFollowPin(PartitionKey, Base):
    __tablename__ = "mobile_follow_pins"
    __table_args__ = (lease_fk(),)
    lease_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    row_number: Mapped[int] = mapped_column(Integer, primary_key=True)
    subject_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"))
    person_revision: Mapped[int | None] = mapped_column(BigInteger)
    following: Mapped[bool | None] = mapped_column(Boolean)
    revision: Mapped[int | None] = mapped_column(BigInteger)
    ordinal: Mapped[int | None] = mapped_column(Integer)
    logical_bytes: Mapped[int] = mapped_column(Integer)


class MobileFollowPageThrottle(PartitionKey, Base):
    __tablename__ = "mobile_follow_page_throttles"
    __table_args__ = (lease_fk(),)
    lease_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    page_key: Mapped[int] = mapped_column(Integer, primary_key=True)
    rate_limited: Mapped[bool] = mapped_column(Boolean, server_default="false")


class MobileFollowApproval(PartitionKey, Base):
    __tablename__ = "mobile_follow_approvals"
    __table_args__ = (
        parent_fk(),
        UniqueConstraint(*KEY, "challenge_digest"),
        Index("ix_mobile_follow_approvals_expiry", "expires_at", *KEY),
    )
    device_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    challenge_digest: Mapped[bytes] = mapped_column(LargeBinary)
    owner_generation: Mapped[int] = mapped_column(BigInteger)
    status: Mapped[str] = mapped_column(String(12), server_default="pending")
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("clock_timestamp()"))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class MobileFollowConsent(PartitionKey, Base):
    __tablename__ = "mobile_follow_consents"
    __table_args__ = (parent_fk(), Index("ix_mobile_follow_consents_expiry", "expires_at", *KEY))
    consent_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    request_generation: Mapped[int] = mapped_column(BigInteger)
    accepted_generation: Mapped[int] = mapped_column(BigInteger)
    body_digest: Mapped[bytes] = mapped_column(LargeBinary)
    accepted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("clock_timestamp()"))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class MobileFollowNonce(PartitionKey, Base):
    __tablename__ = "mobile_follow_nonces"
    __table_args__ = (parent_fk(), UniqueConstraint(*KEY, "nonce_digest"))
    device_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    nonce_digest: Mapped[bytes] = mapped_column(LargeBinary)
    owner_generation: Mapped[int] = mapped_column(BigInteger)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("clock_timestamp()"))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class MobileFollowPrivacyAction(PartitionKey, Base):
    __tablename__ = "mobile_follow_privacy_actions"
    __table_args__ = (
        parent_fk(),
        CheckConstraint(
            "(kind='removal' AND body_digest IS NULL) OR "
            "(kind='withdrawal' AND body_digest IS NOT NULL AND octet_length(body_digest)=32)"
        ),
        Index(
            "uq_mobile_follow_current_recovery", *KEY, unique=True, postgresql_where=text("recovery_mode='state_only'")
        ),
        Index(
            "uq_mobile_follow_nonce_lookup",
            *KEY,
            "device_id",
            "nonce_digest",
            unique=True,
            postgresql_where=text("nonce_digest IS NOT NULL"),
        ),
        Index("ix_mobile_follow_privacy_expiry", "expires_at", *KEY, postgresql_where=text("expires_at IS NOT NULL")),
    )
    action_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    kind: Mapped[str] = mapped_column(String(12))
    recovery_mode: Mapped[str] = mapped_column(String(16))
    device_id: Mapped[str | None] = mapped_column(String(128))
    nonce_digest: Mapped[bytes | None] = mapped_column(LargeBinary)
    body_digest: Mapped[bytes | None] = mapped_column(LargeBinary)
    original_generation: Mapped[int] = mapped_column(BigInteger)
    fenced_generation: Mapped[int] = mapped_column(BigInteger)
    status: Mapped[str] = mapped_column(String(16), server_default="pending")
    worker_cursor: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    logical_bytes: Mapped[int] = mapped_column(Integer, server_default="0")
    admitted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("clock_timestamp()"))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
