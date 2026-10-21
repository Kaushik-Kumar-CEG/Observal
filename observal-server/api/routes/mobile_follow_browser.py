# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Dormant 1.0.5 browser approval routes. Do NOT include this router until
all follow routes, the approved browser UI and privacy gates are complete.
"""

import jwt
from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from pydantic import BaseModel, ConfigDict, Field, StrictBool
from sqlalchemy.ext.asyncio import AsyncSession

import services.dynamic_settings as settings
from api.deps import get_db
from services.jwt_service import MOBILE_CLIENT_ID, decode_access_token
from services.mobile_follow_browser import (
    consume_grant_before_mint,
    enforce_post_limit,
    issuer_origin,
    require_browser_request,
    verification_uri,
)


class BrowserErrorRoute(APIRoute):
    """Apply the frozen Error envelope even for framework parsing and dependency denials."""

    def get_route_handler(self):
        handler = super().get_route_handler()

        async def bounded_handler(request):
            try:
                await enforce_post_limit(request)
                if request.url.path.endswith("/write-approval"):
                    origin = issuer_origin(
                        settings.get_sync("deployment.public_url"), settings.get_sync("deployment.frontend_url")
                    )
                    require_browser_request(request, origin)
                return await handler(request)
            except RequestValidationError:
                return JSONResponse(status_code=400, content={"error": "invalid_request"})
            except HTTPException as exc:
                code = {
                    400: "invalid_request",
                    401: "unauthorized",
                    403: "restricted",
                    409: "generation_conflict",
                    413: "too_large",
                    415: "invalid_request",
                    503: "unavailable",
                }.get(exc.status_code, "unavailable")
                return JSONResponse(
                    status_code=exc.status_code if exc.status_code in (400, 401, 403, 409, 413, 415, 503) else 503,
                    content={"error": code},
                )

        return bounded_handler


router = APIRouter(prefix="/api/v1/mobile-follow-sync/v1", tags=["mobile-follow-sync"], route_class=BrowserErrorRoute)


class ApprovalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    user_code: str = Field(min_length=6, max_length=32)
    approve: StrictBool


@router.post("/write-authorization")
async def write_authorization(
    request: Request, authorization: str | None = Header(None), db: AsyncSession = Depends(get_db)
):
    from services import mobile_follow_auth as auth

    principal = await auth.authorize_follow_read(request, authorization, db)
    origin = issuer_origin(settings.get_sync("deployment.public_url"), settings.get_sync("deployment.frontend_url"))
    code = await auth.create_challenge(db, principal)
    uri = verification_uri(origin, code)
    await db.commit()
    return dict(
        user_code=code,
        verification_uri=uri,
        verification_origins=[origin],
        expires_in=auth.CHALLENGE_SECONDS,
        owner_generation=principal.generation,
    )


@router.post("/write-approval")
async def write_approval(
    request: Request,
    body: ApprovalRequest,
    authorization: str | None = Header(None),
    db: AsyncSession = Depends(get_db),
):
    from services import mobile_follow_auth as auth

    origin = issuer_origin(settings.get_sync("deployment.public_url"), settings.get_sync("deployment.frontend_url"))
    # A signed phone token is never browser authentication, even without an
    # Origin header. Cross-origin desktop requests are still rejected below.
    if authorization and authorization.startswith("Bearer "):
        try:
            candidate = decode_access_token(authorization[7:].strip(), allow_mobile=True)
            if candidate.get("client_id") == MOBILE_CLIENT_ID:
                raise HTTPException(401, {"error": "unauthorized"})
        except jwt.InvalidTokenError:
            pass
    require_browser_request(request, origin)
    principal = await auth.authorize_browser_approval(request, authorization, db)
    if body.approve is not True:
        raise HTTPException(400, "Approval must be explicit")
    await auth.approve_challenge(db, principal, body.user_code)
    await db.commit()
    return {"state": "approved"}


@router.post("/write-grant")
async def write_grant(request: Request, authorization: str | None = Header(None), db: AsyncSession = Depends(get_db)):
    from services import mobile_follow_auth as auth

    principal = await auth.authorize_follow_read(request, authorization, db)
    token, lifetime = await consume_grant_before_mint(db, principal)
    return dict(
        token_type="bearer",
        access_token=token,
        expires_in=lifetime,
        client_id=auth.MOBILE_CLIENT_ID,
        audience=auth.AUDIENCE,
        scope=auth.SCOPE,
        owner_generation=principal.generation,
    )
