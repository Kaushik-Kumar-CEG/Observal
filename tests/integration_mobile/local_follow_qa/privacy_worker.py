# SPDX-FileCopyrightText: 2026 Kaushik Kumar <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Explicitly local QA privacy poller; only the disposable DATABASE_URL may run here."""

import asyncio
import os
import signal

from sqlalchemy.engine import make_url

from database import engine
from jobs.mobile_follow_privacy import run_mobile_follow_privacy


async def main() -> None:
    url = make_url(os.environ["DATABASE_URL"])
    if os.environ.get("MOBILE_FOLLOW_LOCAL_QA") != "1" or url.host != "127.0.0.1" or url.database != "followqa":
        raise RuntimeError("Disposable loopback follow QA database required")
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for event in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(event, stop.set)
    ctx: dict = {}
    try:
        while not stop.is_set():
            await run_mobile_follow_privacy(ctx)
            try:
                await asyncio.wait_for(stop.wait(), timeout=1)
            except TimeoutError:
                pass
    finally:
        await engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())
