# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Default-closed 1.0.5 route installation and per-request operator switch.

The installation flag only exposes route shapes. It is not product consent:
per-request DB approval is required, including for browser grant issuance.
Worker erasure deliberately has no dependency on this switch so revocation
continues after an operator disables new follow activity.
"""

import os

from fastapi import Depends, HTTPException
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from api.deps import get_db

# Separate explicit install action plus DB approval prevents a routine mobile
# auth flag or stale settings cache from silently enabling 17 routes.
ROUTE_INSTALL_ENV = "OBSERVAL_FOLLOW_SYNC_V105_ROUTE_INSTALL"
ACK_KEY = "mobile.follow_sync_v105_owner_decisions_ack"
ENABLE_KEY = "mobile.follow_sync_v105_operator_enabled"
ACK_VALUE = "owner-approved-v105-quota-consent-storage-recovery"


def routes_installed() -> bool:
    return os.environ.get(ROUTE_INSTALL_ENV) == "1"


async def require_operator_approval(db: AsyncSession = Depends(get_db)) -> None:
    try:
        entries = dict(
            (
                await db.execute(
                    text("SELECT key,value FROM enterprise_config WHERE key IN (:ack,:enabled)"),
                    {"ack": ACK_KEY, "enabled": ENABLE_KEY},
                )
            ).all()
        )
    except Exception as exc:
        # Fail closed on DB loss; never let a stale in-memory/Redis setting
        # authorize an already admitted approval or operation.
        raise HTTPException(503, "follow sync approval store unavailable", headers={"Retry-After": "1"}) from exc
    if entries.get(ACK_KEY) != ACK_VALUE or entries.get(ENABLE_KEY) != "true":
        raise HTTPException(404, "follow sync not enabled")
