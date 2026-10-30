# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""LOCAL-only, read-only Pi history qualification. Never point this at a tunnel.

Run with MOBILE_LOCAL_HISTORY_AUDIT=1 and local DATABASE_URL, CLICKHOUSE_URL.
No database writes, raw transcripts, identities or small-cell values are output.
A protected target requires separate, explicit owner authorization and a
reviewed aggregate-safe operating procedure; this script refuses non-loopback.
"""

import asyncio
import json
import os
import sys
from pathlib import Path
from urllib.parse import urlparse

from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "observal-server"), str(ROOT / "packages/observal-shared")]


def _local_only() -> None:
    if os.environ.get("MOBILE_LOCAL_HISTORY_AUDIT") != "1":
        raise SystemExit("Local history audit is opt-in and read-only")
    for name in ("DATABASE_URL", "CLICKHOUSE_URL"):
        value = os.environ.get(name, "")
        try:
            host = make_url(value).host if name == "DATABASE_URL" else urlparse(value).hostname
        except (ValueError, AttributeError, ArgumentError):
            host = None
        if host != "127.0.0.1":
            raise SystemExit("History audit requires explicit 127.0.0.1 database origins")


async def main() -> None:
    from services.mobile_history_audit import audit_local_history

    try:
        result = await asyncio.wait_for(audit_local_history(limit=10), timeout=30)
    except Exception as exc:
        # The shared ClickHouse client otherwise logs the exception's HTTP URL,
        # which can include its password query parameter. Never render its text.
        raise SystemExit(f"Local history audit failed ({type(exc).__name__})") from None
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    _local_only()  # before any source/client imports or network access
    os.environ["NO_PROXY"] = "*"
    os.environ["no_proxy"] = "*"
    from loguru import logger as optic

    optic.remove()  # the server's shared client may otherwise log credential-bearing failure URLs
    asyncio.run(main())
