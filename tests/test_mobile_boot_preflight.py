# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Read-only boot proof cannot mistake mobile-enabled off-clock for unconfigured."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from services import mobile_boot_preflight as preflight


class QueryResult:
    def __init__(self, rows):
        self.rows = rows

    def one_or_none(self):
        return self.rows[0] if self.rows else None

    def all(self):
        return self.rows


class Database:
    def __init__(self, *, clock, auth, head, trigger=True, browser_proof_column=True):
        self.clock = clock
        self.auth = auth
        self.head = head
        self.trigger = trigger
        self.browser_proof_column = browser_proof_column

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None

    async def execute(self, statement, *_args):
        sql = str(statement)
        if "pg_settings" in sql:
            return QueryResult([SimpleNamespace(setting=self.clock, pending_restart=False)])
        if "enterprise_config" in sql:
            return QueryResult([("mobile.auth_enabled", "true" if self.auth else "false")])
        if "mobile_read_controls" in sql:
            return QueryResult([SimpleNamespace(blocked=True, source_policy_ready=True)])
        raise AssertionError(sql)

    async def scalar(self, statement):
        sql = str(statement)
        if "pg_trigger" in sql:
            return self.trigger
        if "pg_attribute" in sql:
            assert "to_regclass('mobile_follow_approvals')" in sql
            assert "browser_action_proven" in sql
            assert "NOT a.attisdropped" in sql
            return self.browser_proof_column
        if "to_regclass" in sql:
            return True
        if "alembic_version" in sql:
            return self.head
        raise AssertionError(sql)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("clock", "auth", "head", "expected"),
    [
        ("off", True, preflight.MOBILE_SCHEMA_HEAD, 2),
        ("off", False, preflight.MOBILE_SCHEMA_HEAD, 0),
        ("on", True, preflight.MOBILE_SCHEMA_HEAD, 0),
        ("on", False, "077_mobile_erasure_epoch_guard", 2),
        ("on", False, "079_mobile_follow_sync_state", 2),
    ],
)
async def test_helm_per_pod_check_reads_actual_mobile_flag_before_off_clock_return(
    monkeypatch, clock, auth, head, expected
):
    db = Database(clock=clock, auth=auth, head=head)
    monkeypatch.setattr(preflight, "engine", SimpleNamespace(connect=lambda: db, dispose=AsyncMock()))
    result = await preflight.inspect_mobile_postgres()
    if head == preflight.MOBILE_SCHEMA_HEAD:
        assert result.auth_enabled is auth
    assert await preflight.main(require_schema=True) == expected
    if head == "079_mobile_follow_sync_state":
        assert result.status == "OLD_OR_INCOMPATIBLE_SCHEMA"


@pytest.mark.asyncio
async def test_schema_stamp_without_enabled_079_erasure_trigger_refuses_api_and_worker_boot(monkeypatch):
    db = Database(clock="on", auth=False, head=preflight.MOBILE_SCHEMA_HEAD, trigger=False)
    monkeypatch.setattr(preflight, "engine", SimpleNamespace(connect=lambda: db, dispose=AsyncMock()))
    result = await preflight.inspect_mobile_postgres()
    assert result.status == "MISSING_FOLLOW_ERASURE_TRIGGER"
    assert not result.follow_erasure_trigger_ready
    assert await preflight.main(require_schema=True) == 2


@pytest.mark.asyncio
async def test_schema_stamp_without_080_browser_proof_column_refuses_boot(monkeypatch):
    db = Database(clock="on", auth=False, head=preflight.MOBILE_SCHEMA_HEAD, browser_proof_column=False)
    monkeypatch.setattr(preflight, "engine", SimpleNamespace(connect=lambda: db, dispose=AsyncMock()))
    result = await preflight.inspect_mobile_postgres()
    assert result.status == "MISSING_FOLLOW_BROWSER_PROOF_COLUMN"
    assert result.follow_erasure_trigger_ready
    assert not result.browser_action_proven_ready
    assert await preflight.main(require_schema=True) == 2
