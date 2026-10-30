# SPDX-FileCopyrightText: 2026 Hari Srinivasan <harisrini21@gmail.com>
# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest


def _resp(text: str = "", status_code: int = 200):
    return SimpleNamespace(status_code=status_code, text=text)


_BASELINE_TABLE_ROWS = "".join(
    f'{{"name":"{name}"}}\n'
    for name in [
        "audit_log",
        "layer_snapshots",
        "security_events",
        "session_events",
        "session_stats_agg",
        "webhook_deliveries",
    ]
)


def test_production_activity_migration_matches_pinned_phase0_ddl():
    from services.clickhouse.migrations import _split_sql

    root = Path(__file__).resolve().parents[1]
    production = _split_sql((root / "observal-server/clickhouse/migrations/008_component_activity.sql").read_text())
    pinned = _split_sql(
        (root / "tests/fixtures/component_insights/clickhouse/projection_tables.sql")
        .read_text()
        .replace("{prefix}", "")
    )[2:]
    assert len(production) == 2
    assert production == pinned
    activity_key = production[0].split("ORDER BY (")[1]
    assert "project_id, user_id, harness, session_id, projection_version" in activity_key
    assert "projection_generation, source_line_offset, source_block_key" in activity_key
    assert "component_id" not in activity_key
    assert "source_revision" in production[1] and "unknown_result_count" in production[1]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("setting", "statement"),
    [
        (None, "ALTER TABLE session_events MODIFY TTL toDate(timestamp) + INTERVAL 90 DAY"),
        ("7", "ALTER TABLE session_events MODIFY TTL toDate(timestamp) + INTERVAL 7 DAY"),
        ("0", "SELECT 1"),
    ],
)
async def test_ch012_renders_validated_pg_retention(monkeypatch, setting, statement):
    import database
    from services.clickhouse import migrations

    db = MagicMock()
    db.scalar = AsyncMock(return_value=setting)
    session = MagicMock()
    session.__aenter__ = AsyncMock(return_value=db)
    session.__aexit__ = AsyncMock(return_value=None)
    monkeypatch.setattr(database, "async_session", lambda: session)
    response = SimpleNamespace(
        raise_for_status=lambda: None,
        json=lambda: {"data": [{"create_table_query": "CREATE TABLE session_events ENGINE = MergeTree ORDER BY x"}]},
    )
    query = AsyncMock(return_value=response)
    monkeypatch.setattr(migrations._client, "_query", query)

    assert await migrations._render_retention_sql("{{SESSION_EVENTS_ROW_RETENTION}};") == statement + ";"
    assert query.await_count == (1 if setting == "0" else 0)


@pytest.mark.asyncio
async def test_ch012_rejects_untrusted_retention_before_ddl(monkeypatch):
    import database
    from services.clickhouse import migrations

    db = MagicMock()
    db.scalar = AsyncMock(return_value="7; DROP TABLE users")
    session = MagicMock()
    session.__aenter__ = AsyncMock(return_value=db)
    session.__aexit__ = AsyncMock(return_value=None)
    monkeypatch.setattr(database, "async_session", lambda: session)
    with pytest.raises(RuntimeError, match="Invalid PostgreSQL source retention"):
        await migrations._render_retention_sql("{{SESSION_EVENTS_ROW_RETENTION}};")


def test_split_sql_strips_spdx_and_keeps_quoted_semicolon():
    from services.clickhouse.migrations import _split_sql

    sql = """# SPDX-FileCopyrightText: 2026 Hari Srinivasan <harisrini21@gmail.com>
# SPDX-License-Identifier: Apache-2.0
SELECT 'a;b';
SELECT 2;
"""

    assert _split_sql(sql) == ["SELECT 'a;b'", "SELECT 2"]


@pytest.mark.asyncio
async def test_run_clickhouse_migrations_skips_applied_files(tmp_path, monkeypatch):
    from services.clickhouse import migrations

    (tmp_path / "001_done.sql").write_text("SELECT 1;\n")
    (tmp_path / "002_new.sql").write_text("SELECT 2;\nSELECT 3;\n")

    calls: list[tuple[str, dict | None]] = []

    async def fake_query_server(_sql: str):
        return _resp()

    async def fake_query(sql: str, params: dict | None = None, **_kwargs):
        calls.append((sql, params))
        if sql.startswith("SELECT version"):
            return _resp('{"version":"001_done"}\n')
        return _resp()

    monkeypatch.setattr(migrations, "MIGRATIONS_DIR", tmp_path)
    monkeypatch.setattr(migrations, "_query_server", fake_query_server)
    monkeypatch.setattr(migrations._client, "clickhouse_health", AsyncMock(return_value=True))
    monkeypatch.setattr(migrations._client, "_query", fake_query)

    await migrations.run_clickhouse_migrations()

    executed_sql = [sql for sql, _params in calls]
    assert "SELECT 1" not in executed_sql
    assert "SELECT 2" in executed_sql
    assert "SELECT 3" in executed_sql
    assert any(sql.startswith("INSERT INTO clickhouse_schema_migrations") for sql in executed_sql)


@pytest.mark.asyncio
async def test_run_clickhouse_migrations_stamps_existing_baseline(tmp_path, monkeypatch):
    from services.clickhouse import migrations

    (tmp_path / "001_baseline.sql").write_text("SELECT 1;\n")
    (tmp_path / "002_new.sql").write_text("SELECT 2;\n")

    calls: list[tuple[str, dict | None]] = []

    async def fake_query_server(_sql: str):
        return _resp()

    async def fake_query(sql: str, params: dict | None = None, **_kwargs):
        calls.append((sql, params))
        if sql.startswith("SELECT version"):
            return _resp()
        if "FROM system.tables" in sql:
            return _resp(_BASELINE_TABLE_ROWS)
        return _resp()

    monkeypatch.setattr(migrations, "MIGRATIONS_DIR", tmp_path)
    monkeypatch.setattr(migrations, "_query_server", fake_query_server)
    monkeypatch.setattr(migrations._client, "clickhouse_health", AsyncMock(return_value=True))
    monkeypatch.setattr(migrations._client, "_query", fake_query)

    await migrations.run_clickhouse_migrations()

    executed_sql = [sql for sql, _params in calls]
    assert "SELECT 1" not in executed_sql
    assert "SELECT 2" in executed_sql
    inserts = [params for sql, params in calls if sql.startswith("INSERT INTO clickhouse_schema_migrations")]
    assert {params["param_version"] for params in inserts if params} == {"001_baseline", "002_new"}
