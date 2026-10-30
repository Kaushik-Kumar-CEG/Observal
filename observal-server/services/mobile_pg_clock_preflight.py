# SPDX-FileCopyrightText: 2026 Observal Contributors
# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0

"""Refuse migrations on mobile-enabled stores without a running PG commit clock."""

import asyncio

from sqlalchemy import text

from database import engine


async def check_commit_clock() -> None:
    try:
        async with engine.connect() as conn:
            row = (
                await conn.execute(
                    text("SELECT setting,pending_restart FROM pg_settings WHERE name=:name"),
                    {"name": "track_commit_timestamp"},
                )
            ).one_or_none()
            if row is not None and row.setting == "on" and not row.pending_restart:
                return
            has_config = await conn.scalar(text("SELECT to_regclass(:name) IS NOT NULL"), {"name": "enterprise_config"})
            enabled = (
                (
                    await conn.scalar(
                        text("SELECT value FROM enterprise_config WHERE key=:key"), {"key": "mobile.auth_enabled"}
                    )
                )
                == "true"
                if has_config
                else False
            )
            if enabled:
                raise RuntimeError("MOBILE_PG_COMMIT_CLOCK_UNAVAILABLE: restart PostgreSQL before migration")
            print("MOBILE_PG_COMMIT_CLOCK_UNAVAILABLE: mobile remains disabled")
    finally:
        await engine.dispose()


if __name__ == "__main__":
    asyncio.run(check_commit_clock())
