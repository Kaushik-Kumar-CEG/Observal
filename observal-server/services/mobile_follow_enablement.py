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
RISK_ACK_VALUE = "owner-accepted-unreviewed-synthetic-only-v1"
RISK_KEY = "mobile.follow_sync_v105_synthetic_risk_sha256"
RISK_INSTALL_ENV = "OBSERVAL_FOLLOW_SYNTHETIC_RISK_INSTALL"


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
STATUS_RECOVERY_ROUTE = ("GET", "/api/v1/mobile-follow-sync/v1/operations/{operation_id}")
RECOVERY_ROUTES = frozenset(
    {
        # Historical status requires an intact acknowledgement and fresh worker
        # even if the operator switch is off. The read handler checks owner,
        # device, cohort, partition and erasure. It never returns a follow list.
        STATUS_RECOVERY_ROUTE,
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
        if (request.method, route.path) == STATUS_RECOVERY_ROUTE:
            await require_status_recovery_approval(db)
        return
    await require_operator_approval(db)


async def _gate_entries(db: AsyncSession) -> dict[str, str]:
    try:
        # Match the operator/retention order: project barrier before config rows.
        # Otherwise an admitted route can hold config FOR SHARE while waiting on
        # an operator's project lock, as that operator waits to clear its config.
        from observal_shared.migration.constants import DEFAULT_PROJECT_ID

        await db.execute(
            text("SELECT pg_advisory_xact_lock_shared(hashtextextended(:key, 0))"),
            {"key": "mobile-read:" + str(DEFAULT_PROJECT_ID)},
        )
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
    return entries


async def _ack_authorized(db: AsyncSession, entries: dict[str, str]) -> bool:
    if entries.get(ACK_KEY) == ACK_VALUE:
        return True
    if entries.get(ACK_KEY) != RISK_ACK_VALUE or os.environ.get(RISK_INSTALL_ENV) != "1":
        return False
    # Admission remains under the shared project lock. Risk cannot authorize a
    # live cohort, expired/unconfigured pair, changed server, or real identities.
    from uuid import UUID

    from services.mobile_read_control import synthetic_principals_valid

    values = dict(
        (
            await db.execute(
                text("""SELECT key,value FROM enterprise_config
        WHERE key IN ('mobile.auth_enabled','mobile.synthetic_test_enabled','mobile.synthetic_test_ack',
        'mobile.synthetic_test_server_id','mobile.synthetic_test_viewer_id','mobile.synthetic_test_self_user_viewer_id',
        'trace_headlines','mobile.trace_qualification_ack','mobile.trace_qualification_server_id',:risk) FOR SHARE"""),
                {"risk": RISK_KEY},
            )
        ).all()
    )
    if (
        values.get("mobile.auth_enabled") != "true"
        or values.get("mobile.synthetic_test_enabled") != "true"
        or values.get("mobile.synthetic_test_ack") != "isolated-disposable-synthetic-only-v1"
        or values.get("trace_headlines") == "true"
        or values.get("mobile.trace_qualification_ack")
        or values.get("mobile.trace_qualification_server_id")
    ):
        return False
    digest = values.get(RISK_KEY, "")
    if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        return False
    try:
        author = UUID(values.get("mobile.synthetic_test_viewer_id", ""))
        user = UUID(values.get("mobile.synthetic_test_self_user_viewer_id", ""))
        server = UUID(values.get("mobile.synthetic_test_server_id", ""))
    except (ValueError, TypeError):
        return False
    if not await db.scalar(
        text("""SELECT EXISTS (SELECT 1 FROM mobile_read_controls c, mobile_server_identity s
        WHERE c.project_id='default' AND NOT c.blocked AND NOT c.revocation_pending AND c.source_policy_ready
        AND c.synthetic_expires_at > clock_timestamp() AND s.singleton=true AND s.server_id=:server)"""),
        {"server": server},
    ):
        return False
    if not await synthetic_principals_valid(db, author, user):
        return False
    return not await db.scalar(
        text("""SELECT EXISTS (SELECT 1 FROM mobile_follow_subjects
        WHERE project_id='default' AND owner_id IN (:author,:actor)
        AND cohort IN ('synthetic-author','synthetic-user') AND subject_id NOT IN (:author,:actor))"""),
        {"author": author, "actor": user},
    )


async def require_status_recovery_approval(db: AsyncSession) -> None:
    entries = await _gate_entries(db)
    if (
        not await _ack_authorized(db, entries)
        or entries.get(ENABLE_KEY) not in {"true", "false"}
        or entries.get(WORKER_KEY) != "running"
    ):
        raise HTTPException(404, "follow sync status recovery not enabled")


async def require_operator_approval(db: AsyncSession = Depends(get_db)) -> None:
    entries = await _gate_entries(db)
    if (
        not await _ack_authorized(db, entries)
        or entries.get(ENABLE_KEY) != "true"
        or entries.get(WORKER_KEY) != "running"
    ):
        raise HTTPException(404, "follow sync not enabled")
