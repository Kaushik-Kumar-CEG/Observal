# SPDX-FileCopyrightText: 2026 Kaushik Kumar <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Disposable projection poller; never target a nonlocal PostgreSQL or ClickHouse."""

import asyncio
import os
import signal
from urllib.parse import urlsplit

from sqlalchemy.engine import make_url

from database import engine
from jobs.mobile_evidence import run_mobile_projection_queue


async def main() -> None:
    pg = make_url(os.environ["DATABASE_URL"])
    ch = urlsplit(os.environ["CLICKHOUSE_URL"])
    if (
        os.environ.get("MOBILE_FOLLOW_LOCAL_QA") != "1"
        or pg.host != "127.0.0.1"
        or pg.database != "followqa"
        or ch.scheme != "http"
        or ch.hostname != "127.0.0.1"
        or ch.path != "/followqa"
        or ch.username != "followqa"
        or ch.port is None
    ):
        raise RuntimeError("Disposable loopback follow QA sources required")
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for event in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(event, stop.set)
    ctx: dict = {}
    try:
        while not stop.is_set():
            await run_mobile_projection_queue(ctx)
            try:
                await asyncio.wait_for(stop.wait(), timeout=1)
            except TimeoutError:
                pass
    finally:
        await engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())
