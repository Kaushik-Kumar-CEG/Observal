# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Dormant follow browser boundary. Importing this module registers no routes.

Only the explicit deployment issuer is trusted. Neither Host nor forwarded headers
are suitable for constructing a code-bearing verification URL or a CSRF allowlist.
"""

import uuid
from datetime import UTC, datetime
from urllib.parse import quote, urlsplit

from fastapi import HTTPException, Request
from sqlalchemy import select


def issuer_origin(public_url: str, frontend_url: str) -> str:
    """Require the browser and API to share one configured HTTPS issuer."""

    def origin(value: str) -> str:
        try:
            url = urlsplit(value)
            if (
                url.scheme != "https"
                or not url.hostname
                or url.username is not None
                or url.password is not None
                or url.query
                or url.fragment
                or url.path not in ("", "/")
                or (url.port is None and ":" in url.netloc and not url.netloc.startswith("["))
            ):
                raise ValueError("invalid issuer")
            host = url.hostname.lower()
            port = url.port
            return f"https://{host if ':' not in host else f'[{host}]'}{f':{port}' if port not in (None, 443) else ''}"
        except (ValueError, TypeError):
            raise HTTPException(503, "Follow browser issuer unavailable") from None

    if not public_url or not frontend_url:
        raise HTTPException(503, "Follow browser issuer unavailable")
    api, web = origin(public_url), origin(frontend_url)
    if api != web:
        raise HTTPException(503, "Follow browser issuer unavailable")
    return api


def require_browser_request(request: Request, origin: str) -> None:
    """Bearer-only JSON API; origin is required even when CORS would deny reads."""
    if request.method != "POST":
        raise HTTPException(405, "Method not allowed")
    if len(request.headers.getlist("origin")) != 1 or request.headers.get("origin") != origin:
        raise HTTPException(403, "Invalid browser origin")
    if request.headers.get("sec-fetch-site") not in (None, "same-origin"):
        raise HTTPException(403, "Invalid browser origin")
    if request.headers.get("content-type", "").lower().split(";", 1)[0].strip() != "application/json":
        raise HTTPException(415, "JSON required")
    authorization = request.headers.get("authorization", "")
    if (
        len(request.headers.getlist("authorization")) != 1
        or not authorization.startswith("Bearer ")
        or not authorization[7:].strip()
    ):
        raise HTTPException(401, "Browser bearer required")
    # Cookies cannot act as an alternative authorization mechanism. The follow
    # dependency additionally rejects phone and follow-write JWTs.


async def enforce_post_limit(request: Request) -> None:
    """Reject oversized POST bodies before JSON decoding or dependency work."""
    size = 0
    chunks = []
    async for chunk in request.stream():
        size += len(chunk)
        if size > 4096:
            raise HTTPException(413, {"error": "too_large"})
        chunks.append(chunk)
    request._body = b"".join(chunks)  # Reuse the bounded bytes for FastAPI's JSON parsing.


def verification_uri(origin: str, code: str) -> str:
    """A code is not a bearer; never include one in server-side logs or redirects."""
    if (
        not isinstance(code, str)
        or not 20 <= len(code) <= 32
        or not code.isascii()
        or not all(char.isalnum() or char in "-_" for char in code)
    ):
        raise HTTPException(503, "Invalid follow challenge")
    return f"{origin}/follow/approve?code={quote(code, safe='')}"


async def consume_grant_before_mint(db, principal) -> tuple[str, int]:
    """Commit the one-use approval before signing, across all API processes.

    The read dependency has taken a shared partition lock. End that transaction
    first: two simultaneous shared-to-exclusive upgrades would deadlock. Repeat
    account, Redis, cohort, server and generation checks inside the new transaction.
    Do not return an uncommitted JWT on commit failure.
    """
    from models.mobile_follow_sync import MobileFollowApproval
    from services import mobile_follow_auth as auth
    from services.crypto import sign_token

    if principal.device_id is None:
        raise HTTPException(401, "Invalid follow credential")
    device, payload = principal.device_id, principal.payload
    owner_id = principal.user.id
    await db.commit()
    user = await auth._account(payload, db, device_id=device)
    server = await auth._identity(db)
    if user.id != owner_id or server != principal.server_id or await auth._cohort(db, user, server) != principal.cohort:
        raise HTTPException(401, "Invalid follow credential")
    partition = await auth._partition(db, user, server, principal.cohort, exclusive=True)
    key = dict(server_id=server, project_id=auth.PROJECT, owner_id=owner_id, cohort=principal.cohort)
    approval = await db.scalar(
        select(MobileFollowApproval)
        .where(
            *[getattr(MobileFollowApproval, name) == value for name, value in key.items()],
            MobileFollowApproval.device_id == device,
        )
        .with_for_update()
    )
    if partition.owner_generation != principal.generation:
        raise HTTPException(401, "Invalid follow credential")
    if partition.consent_state != "available" or partition.removal_state != "none":
        # The mobile read credential is still valid during a protected opt-out;
        # report the frozen restricted state, not an invalid token. Do not
        # mint, revive or reveal an approval (the barrier already removed it).
        raise HTTPException(403, "Follow access restricted")
    if approval is None or approval.status == "pending":
        raise HTTPException(403, "Device approval required")
    if (
        approval.status != "approved"
        or approval.owner_generation != partition.owner_generation
        or approval.expires_at <= datetime.now(UTC)
    ):
        raise HTTPException(401, "Invalid follow credential")
    generation = partition.owner_generation
    # Retain the one active device row as a bounded consumed marker. This
    # distinguishes a never-approved second phone (403) from reuse of a grant
    # already consumed by this phone (401) across API processes.
    approval.status = "revoked"
    approval.approved_at = None
    await db.flush()
    await db.commit()  # One-use consumption is durable BEFORE token minting.
    now = datetime.now(UTC)
    issued = int(now.timestamp())
    return sign_token(
        dict(
            sub=str(owner_id),
            jti=str(uuid.uuid4()),
            type="follow-write",
            client_id=auth.MOBILE_CLIENT_ID,
            aud=auth.AUDIENCE,
            scope=auth.SCOPE,
            device_id=device,
            server_id=str(server),
            project_id=auth.PROJECT,
            cohort=principal.cohort,
            owner_generation=generation,
            iat=issued,
            iat_us=issued * 1_000_000 + now.microsecond,
            exp=issued + auth.MAX_TOKEN_SECONDS,
        )
    ), auth.MAX_TOKEN_SECONDS
