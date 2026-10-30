# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Default-closed 1.0.5 route installation and per-request operator switch.

The installation flag only exposes route shapes. It is not product consent:
per-request DB approval is required for new activity, including browser grant
issuance. Owner withdrawal and receipt recovery remain available after the
switch closes; worker erasure likewise remains independent of that switch.
"""

import os

from fastapi import Depends, HTTPException, Request
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from api.deps import get_db

# Separate explicit install action plus DB approval prevents a routine mobile
# auth flag or stale settings cache from silently enabling 17 routes.
ROUTE_INSTALL_ENV = "OBSERVAL_FOLLOW_SYNC_V105_ROUTE_INSTALL"
ACK_KEY = "mobile.follow_sync_v105_owner_decisions_ack"
ENABLE_KEY = "mobile.follow_sync_v105_operator_enabled"
WORKER_KEY = "mobile.follow_sync_v105_worker_heartbeat"
ACK_VALUE = "owner-approved-v105-quota-consent-storage-recovery"


def routes_installed() -> bool:
    return os.environ.get(ROUTE_INSTALL_ENV) == "1"


async def require_user_verifying_approval(request: Request) -> None:
    """Mark operator-gated routes; only the normal router can issue epoch-1 grants."""
    request.state.normal_follow_router = True


async def require_user_verifying_mutation(request: Request) -> None:
    """Require independent browser intent for normal consent, not for phone writes."""
    request.state.normal_follow_router = True


# Recovery routes are still installed only by the explicit startup flag. Their
# handlers retain independent credential, owner/cohort, and privacy-store fences;
# the operator switch controls new activity, not an owner's ability to erase it.
RECOVERY_ROUTES = frozenset(
    {
        # Only an already approved, browser-proven phone can pass the handler's
        # owner/device/generation checks. No new approval is possible here.
        ("POST", "/api/v1/mobile-follow-sync/v1/write-grant"),
        ("POST", "/api/v1/mobile-follow-sync/v1/consent/withdraw"),
        ("GET", "/api/v1/mobile-follow-sync/v1/consent/withdrawals/{withdrawal_id}"),
        ("POST", "/api/v1/mobile-follow-sync/v1/removals/lookup"),
        ("GET", "/api/v1/mobile-follow-sync/v1/removals/{removal_id}"),
    }
)


async def require_activity_or_recovery(request: Request, db: AsyncSession = Depends(get_db)) -> None:
    route = request.scope.get("route")
    if route is not None and (request.method, route.path) in RECOVERY_ROUTES:
        return
    await require_operator_approval(db)


async def require_operator_approval(db: AsyncSession = Depends(get_db)) -> None:
    try:
        entries = dict(
            (
                await db.execute(
                    text("""SELECT key,value FROM enterprise_config
                    WHERE key IN (:ack,:enabled,:worker)
                      AND (key <> :worker OR updated_at >= clock_timestamp() - interval '90 seconds')
                    ORDER BY key FOR SHARE"""),
                    {"ack": ACK_KEY, "enabled": ENABLE_KEY, "worker": WORKER_KEY},
                )
            ).all()
        )
    except Exception as exc:
        # Fail closed on DB loss; never let a stale in-memory/Redis setting
        # authorize an already admitted approval or operation.
        raise HTTPException(503, "follow sync approval store unavailable", headers={"Retry-After": "1"}) from exc
    if entries.get(ACK_KEY) != ACK_VALUE or entries.get(ENABLE_KEY) != "true" or entries.get(WORKER_KEY) != "running":
        raise HTTPException(404, "follow sync not enabled")
