# SPDX-FileCopyrightText: 2026 Hari Srinivasan <harisrini21@gmail.com>
# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""ClickHouse runtime initialization and resource-tuning settings."""

from loguru import logger as optic

import services.clickhouse._settings as _ch_settings
import services.clickhouse.client as _client

# ── Resource tuning ───────────────────────────────────────────────────────────

# Maps enterprise_config keys to ClickHouse SET-able settings.
# Only whitelisted settings are accepted to avoid SQL injection.
RESOURCE_SETTINGS_MAP: dict[str, tuple[str, type]] = {
    "resource.max_query_memory_mb": ("max_memory_usage", int),
    "resource.group_by_spill_mb": ("max_bytes_before_external_group_by", int),
    "resource.sort_spill_mb": ("max_bytes_before_external_sort", int),
    "resource.join_memory_mb": ("max_bytes_in_join", int),
}


# Re-export for backwards compat (tests and __init__ reference these)
DEFAULT_QUERY_SETTINGS = _ch_settings.DEFAULT_QUERY_SETTINGS
_resource_overrides = _ch_settings._resource_overrides


async def apply_resource_settings(overrides: dict[str, str] | None = None):
    """Load resource tuning settings and inject them into every ClickHouse query.

    Reads from enterprise_config (Postgres) unless *overrides* is supplied.
    """
    resource_values: dict[str, str] = {}

    if overrides is not None:
        resource_values = overrides
    else:
        try:
            from sqlalchemy import select

            from database import async_session
            from models.enterprise_config import EnterpriseConfig

            async with async_session() as db:
                result = await db.execute(select(EnterpriseConfig).where(EnterpriseConfig.key.like("resource.%")))
                for cfg in result.scalars().all():
                    resource_values[cfg.key] = cfg.value
        except Exception as e:
            optic.warning("could not read resource settings from DB (using defaults): {}", e)

    if not resource_values:
        return

    new_overrides: dict[str, str] = {}
    for config_key, (ch_setting, cast) in RESOURCE_SETTINGS_MAP.items():
        raw = resource_values.get(config_key)
        if raw is None:
            continue
        try:
            mb = cast(raw)
            if mb <= 0:
                continue
            new_overrides[ch_setting] = str(mb * 1_000_000)
        except (ValueError, TypeError):
            optic.warning("invalid resource setting {}={}, skipping", config_key, raw)

    _ch_settings._resource_overrides.clear()
    _ch_settings._resource_overrides.update(new_overrides)
    optic.info("ClickHouse resource overrides applied: {}", new_overrides)


async def _materialize_if_needed():
    """Conditionally materialize projection and indexes on session_events.

    Only runs MATERIALIZE commands when parts exist that lack the projection
    or indexes. Avoids creating new mutations on every server restart.
    """
    try:
        r = await _client._query(
            "SELECT count() AS cnt FROM system.parts "
            "WHERE table = 'session_events' AND database = currentDatabase() "
            "AND active AND NOT has(projections, 'proj_session_view') "
            "FORMAT JSON"
        )
        if r.status_code == 200:
            data = r.json().get("data", [{}])
            if int(data[0].get("cnt", 0)) > 0:
                await _client._query("ALTER TABLE session_events MATERIALIZE PROJECTION proj_session_view")
                optic.info("materialized proj_session_view projection on existing parts")
    except Exception as e:
        optic.warning("could not check projection status: {}", e)

    for idx_name in ("idx_se_event_type", "idx_se_parent_session_id"):
        try:
            r = await _client._query(
                "SELECT count() AS cnt FROM system.parts "
                "WHERE table = 'session_events' AND database = currentDatabase() "
                f"AND active AND NOT has(data_skipping_indices, '{idx_name}') "
                "FORMAT JSON"
            )
            if r.status_code == 200:
                data = r.json().get("data", [{}])
                if int(data[0].get("cnt", 0)) > 0:
                    await _client._query(f"ALTER TABLE session_events MATERIALIZE INDEX {idx_name}")
                    optic.info("materialized index {} on existing parts", idx_name)
        except Exception as e:
            optic.warning("could not check index {} status: {}", idx_name, e)


async def init_clickhouse():
    """Configure ClickHouse runtime settings after migrations have run."""
    optic.info("initializing ClickHouse runtime settings")

    from services.clickhouse.client import clickhouse_health

    if not await clickhouse_health():
        raise RuntimeError(f"ClickHouse unreachable at {_client.CLICKHOUSE_HTTP}")

    await _materialize_if_needed()
    await apply_resource_settings()

    from sqlalchemy import text

    from database import async_session

    # Invalidate all reads before applying the non-transactional ClickHouse
    # TTL. API replicas and the worker observe one PostgreSQL read barrier.
    async with async_session() as db:
        await db.execute(text("SELECT pg_advisory_xact_lock(hashtextextended('mobile-read:default',0))"))
        await db.execute(
            text(
                "UPDATE mobile_read_controls SET source_policy_ready=false,generation=generation+1 "
                "WHERE project_id='default'"
            )
        )
        await db.commit()
    # Hold the exclusive project lock across CH ALTER, metadata readback and
    # readiness commit. Two restarting API replicas could otherwise interleave
    # ALT 90 / ALT 7 and let the losing writer change CH after the winning
    # writer has reopened mobile reads under the wrong whole-row TTL.
    async with async_session() as db:
        await db.execute(text("SELECT pg_advisory_xact_lock(hashtextextended('mobile-read:default',0))"))
        configured = await db.scalar(text("SELECT value FROM enterprise_config WHERE key='data.retention_days'"))
        try:
            retention_days = int(configured) if configured is not None else 90
        except (ValueError, TypeError) as exc:
            raise RuntimeError("Unverifiable ClickHouse source retention policy") from exc
        if not 0 <= retention_days <= 36500:
            raise RuntimeError("Valid ClickHouse source retention required for mobile qualification")
        statement = (
            f"ALTER TABLE session_events MODIFY TTL toDate(timestamp) + INTERVAL {retention_days} DAY"
            if retention_days
            else "ALTER TABLE session_events REMOVE TTL"
        )
        if retention_days == 0:
            before = await _client._query(
                "SELECT create_table_query FROM system.tables WHERE database=currentDatabase() "
                "AND name='session_events' FORMAT JSON"
            )
            before.raise_for_status()
            existing = str((before.json().get("data") or [{}])[0].get("create_table_query") or "")
            # ClickHouse rejects REMOVE TTL if the whole-row TTL is already
            # absent. Do not mistake the 30-day raw_line column TTL for it.
            if " TTL " in existing.split(" ENGINE =", 1)[-1]:
                removed = await _client._query(statement)
                removed.raise_for_status()
        else:
            applied = await _client._query(statement)
            applied.raise_for_status()  # The HTTP client does not raise on 4xx/5xx.
        actual = await _client._query(
            "SELECT create_table_query FROM system.tables WHERE database=currentDatabase() "
            "AND name='session_events' FORMAT JSON"
        )
        actual.raise_for_status()
        import re

        ddl = str((actual.json().get("data") or [{}])[0].get("create_table_query") or "")
        # system.tables has no ttl_expression column in ClickHouse 26.6.
        # Both whole-row and raw-line column TTL must match the source clock.
        whole_row = rf"\bTTL\s+toDate\(timestamp\)\s*\+\s*toIntervalDay\({retention_days}\)"
        engine_clause = ddl.split(" ENGINE =", 1)[-1] if " ENGINE =" in ddl else ""
        correct_row_ttl = bool(re.search(whole_row, engine_clause)) if retention_days else " TTL " not in engine_clause
        raw_column = r"`?raw_line`?\s+String(?:\s+CODEC\(ZSTD\(3\)\))?\s+TTL\s+timestamp\s*\+\s*toIntervalDay\(30\)"
        if not (correct_row_ttl and re.search(raw_column, ddl)):
            raise RuntimeError("ClickHouse whole-row/raw-column TTL did not match verified mobile source policy")
        await db.execute(
            text(
                "UPDATE mobile_read_controls SET source_policy_ready=true,"
                "source_policy_since=COALESCE(source_policy_since,clock_timestamp()) WHERE project_id='default'"
            )
        )
        await db.execute(
            text(
                "INSERT INTO mobile_source_policy_audit(project_id,source_policy_epoch,event,retention_days) "
                "SELECT project_id,source_policy_epoch,'ttl_verified',:days FROM mobile_read_controls "
                "WHERE project_id='default'"
            ),
            {"days": retention_days},
        )
        await db.commit()
    optic.info("ClickHouse mobile source retention verified: {} days", retention_days)
