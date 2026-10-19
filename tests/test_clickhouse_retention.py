# SPDX-FileCopyrightText: 2026 Hari Srinivasan <harisrini21@gmail.com>
# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Verified dual-clock ClickHouse TTL and 067 PostgreSQL deny-first startup."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest


class DB:
    def __init__(self, value=None):
        self.value = value
        self.sql = []
        self.commit_count = 0

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return False

    async def execute(self, statement, params=None):
        self.sql.append((str(statement), params))

    async def scalar(self, statement):
        assert "enterprise_config" in str(statement)
        return self.value

    async def commit(self):
        self.commit_count += 1


def response(ddl="", *, status=200):
    result = MagicMock()
    result.status_code = status
    result.raise_for_status = MagicMock(side_effect=RuntimeError("CH HTTP error") if status >= 400 else None)
    result.json.return_value = {"data": [{"create_table_query": ddl}]}
    return result


def source_table(row_ttl: int | None, *, raw_ttl=True):
    raw = "`raw_line` String TTL timestamp + toIntervalDay(30)" if raw_ttl else "`raw_line` String"
    table = f"CREATE TABLE default.session_events (`timestamp` DateTime64(3, 'UTC'), {raw}) "
    table += "ENGINE = MergeTree ORDER BY timestamp"
    return table + (f" TTL toDate(timestamp) + toIntervalDay({row_ttl})" if row_ttl is not None else "")


@pytest.mark.asyncio
async def test_retention_applies_90_and_audits_only_after_both_ch_clocks_are_verified():
    from services.clickhouse.schema import init_clickhouse

    db = DB()
    ddl = source_table(90)

    async def ch(sql):
        if "SELECT create_table_query" in sql:
            return response(ddl)
        if "MODIFY TTL" in sql:
            assert db.commit_count == 1, "deny must commit before CH mutation"
        return response()

    with (
        patch("database.async_session", new=lambda: db),
        patch("services.clickhouse.client.clickhouse_health", new=AsyncMock(return_value=True)),
        patch("services.clickhouse.schema._materialize_if_needed", new=AsyncMock()),
        patch("services.clickhouse.schema.apply_resource_settings", new=AsyncMock()),
        patch("services.clickhouse.client._query", new=AsyncMock(side_effect=ch)) as query,
    ):
        await init_clickhouse()

    assert sum("MODIFY TTL" in call.args[0] for call in query.call_args_list) == 1
    assert any("INTERVAL 90 DAY" in call.args[0] for call in query.call_args_list)
    assert db.commit_count == 2
    assert [sql for sql, _ in db.sql if "source_policy_ready=true" in sql]
    assert [sql for sql, _ in db.sql if "mobile_source_policy_audit" in sql]


@pytest.mark.asyncio
async def test_retention_zero_removes_existing_whole_row_ttl_but_keeps_raw_line_limit():
    from services.clickhouse.schema import init_clickhouse

    db = DB("0")
    ddl = source_table(7)

    async def ch(sql):
        nonlocal ddl
        if sql.startswith("ALTER TABLE session_events REMOVE TTL"):
            ddl = source_table(None)
        if "SELECT create_table_query" in sql:
            return response(ddl)
        return response()

    with (
        patch("database.async_session", new=lambda: db),
        patch("services.clickhouse.client.clickhouse_health", new=AsyncMock(return_value=True)),
        patch("services.clickhouse.schema._materialize_if_needed", new=AsyncMock()),
        patch("services.clickhouse.schema.apply_resource_settings", new=AsyncMock()),
        patch("services.clickhouse.client._query", new=AsyncMock(side_effect=ch)) as query,
    ):
        await init_clickhouse()
        await init_clickhouse()  # ClickHouse rejects a second REMOVE TTL; the init must be idempotent.
    assert sum("REMOVE TTL" in call.args[0] for call in query.call_args_list) == 1
    assert db.commit_count == 4


@pytest.mark.asyncio
@pytest.mark.parametrize("ddl", [source_table(7), source_table(90, raw_ttl=False), ""])
async def test_mismatched_or_missing_ch_schema_never_reopens_policy(ddl):
    from services.clickhouse.schema import init_clickhouse

    db = DB("90")

    async def ch(sql):
        return response(ddl) if "SELECT create_table_query" in sql else response()

    with (
        patch("database.async_session", new=lambda: db),
        patch("services.clickhouse.client.clickhouse_health", new=AsyncMock(return_value=True)),
        patch("services.clickhouse.schema._materialize_if_needed", new=AsyncMock()),
        patch("services.clickhouse.schema.apply_resource_settings", new=AsyncMock()),
        patch("services.clickhouse.client._query", new=AsyncMock(side_effect=ch)),
        pytest.raises(RuntimeError, match="TTL did not match"),
    ):
        await init_clickhouse()
    assert db.commit_count == 1
    assert not any("source_policy_ready=true" in sql for sql, _ in db.sql)
    assert not any("mobile_source_policy_audit" in sql for sql, _ in db.sql)
