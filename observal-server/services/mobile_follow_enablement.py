# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Default-closed 1.0.5 route installation and per-request operator switch.

The installation flag only exposes route shapes. It is not product consent:
per-request DB approval is required, including for browser grant issuance.
Worker erasure deliberately has no dependency on this switch so revocation
continues after an operator disables new follow activity.
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


async def require_user_verifying_approval() -> None:
    """Do not issue phone write challenges until a reviewed step-up exists.

    A password-recency claim and an Origin header do not attest a human
    browser click; SSO-only accounts have no fresh IdP step-up. The operator
    switch cannot waive this independent security requirement. The disposable
    loopback synthetic QA app intentionally does not mount this dependency.
    """
    raise HTTPException(403, "user-verifying follow approval unavailable")


async def require_user_verifying_mutation(request: Request) -> None:
    """Block consent and follow edits, including previously minted write JWTs.

    Keep privacy withdrawal/removal and receipt recovery independently callable
    behind the operator gate. The local synthetic QA app is not mounted here.
    """
    if request.method == "POST" and request.url.path in {
        "/api/v1/mobile-follow-sync/v1/operations",
        "/api/v1/mobile-follow-sync/v1/consent",
    }:
        # StrictErrorRoute preserves frozen errors only for a typed envelope.
        raise HTTPException(403, {"error": "restricted"})


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
