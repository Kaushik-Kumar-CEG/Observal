# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Allowlisted, uploader-bound v2 identity manifest (not proof of execution)."""

import hashlib
import json
import uuid
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from api.deps import get_current_user, get_db
from api.ratelimit import limiter
from models.mcp import ListingStatus, McpListing, McpVersion
from models.user import User
from observal_shared.migration.constants import DEFAULT_PROJECT_ID

router = APIRouter(prefix="/api/v1/mobile-evidence/v1", tags=["mobile-evidence"])


class ComponentPin(BaseModel):
    id: uuid.UUID
    version: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9.+_-]{0,49}$")
    alias: str = Field(pattern=r"^[A-Za-z0-9_-]{1,128}$")


class LayerRequest(BaseModel):
    harness: Literal["pi"]
    components: list[ComponentPin] = Field(min_length=1, max_length=100)


class LayerReceipt(BaseModel):
    hash: str
    mapped_components: int


def canonical_layer_hash(components: list[ComponentPin]) -> str:
    canonical = sorted([(str(c.id), c.version, c.alias) for c in components])
    return "v2_" + hashlib.sha256(json.dumps(canonical, separators=(",", ":")).encode()).hexdigest()


@router.post("/layers", response_model=LayerReceipt)
@limiter.limit("10/minute")
async def upload_layer(
    request: Request,
    layer: LayerRequest,
    db: AsyncSession = Depends(get_db),
    viewer: User = Depends(get_current_user),
):
    del request
    if len({pin.alias for pin in layer.components}) != len(layer.components):
        raise HTTPException(status_code=422, detail="Duplicate component alias")
    if len({pin.id for pin in layer.components}) != len(layer.components):
        raise HTTPException(status_code=422, detail="Duplicate component ID")
    pins = {pin.id: pin for pin in layer.components}
    matches = (
        await db.execute(
            select(McpListing.id, McpVersion.id, McpVersion.version)
            .join(McpVersion, McpVersion.listing_id == McpListing.id)
            .where(
                McpListing.id.in_(pins),
                McpVersion.status == ListingStatus.approved,
                McpListing.is_private.is_(False),
            )
        )
    ).all()
    resolved: dict[uuid.UUID, uuid.UUID] = {}
    for listing_id, version_id, version in matches:
        if version == pins[listing_id].version:
            resolved[listing_id] = version_id
    # Do not expose which private/unknown/unapproved pin failed.
    if len(resolved) != len(pins):
        raise HTTPException(status_code=422, detail="Unsupported component identity")
    digest = canonical_layer_hash(layer.components)
    params = {"project": str(DEFAULT_PROJECT_ID), "user": viewer.id, "harness": layer.harness, "hash": digest}
    existing = await db.scalar(
        text(
            "SELECT expected_components FROM mobile_verified_layers "
            "WHERE project_id=:project AND user_id=:user AND harness=:harness AND layer_hash=:hash"
        ),
        params,
    )
    if existing is not None:
        count = await db.scalar(
            text(
                "SELECT count(*) FROM mobile_layer_components "
                "WHERE project_id=:project AND user_id=:user AND harness=:harness AND layer_hash=:hash"
            ),
            params,
        )
        if existing != len(pins) or count != existing:
            raise HTTPException(status_code=409, detail="Layer mapping invalidated")
        return LayerReceipt(hash=digest, mapped_components=count)
    await db.execute(
        text(
            "INSERT INTO mobile_verified_layers(project_id,user_id,harness,layer_hash,expected_components) "
            "VALUES (:project,:user,:harness,:hash,:count) ON CONFLICT DO NOTHING"
        ),
        {**params, "count": len(pins)},
    )
    for pin in layer.components:
        await db.execute(
            text(
                "INSERT INTO mobile_layer_components(project_id,user_id,harness,layer_hash,alias,component_id,version_id) "
                "VALUES (:project,:user,:harness,:hash,:alias,:component,:version) ON CONFLICT DO NOTHING"
            ),
            {**params, "alias": pin.alias, "component": pin.id, "version": resolved[pin.id]},
        )
    await db.commit()
    return LayerReceipt(hash=digest, mapped_components=len(pins))
