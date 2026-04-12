from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.deps import get_current_user, get_db, resolve_prefix_id
from models.graphrag import GraphRagListing
from models.hook import HookListing
from models.mcp import ListingStatus, McpListing
from models.prompt import PromptListing
from models.sandbox import SandboxListing
from models.skill import SkillListing
from models.tool import ToolListing
from models.user import User, UserRole
from schemas.mcp import ReviewActionRequest

router = APIRouter(prefix="/api/v1/review", tags=["review"])

LISTING_MODELS = {
    "mcp": McpListing,
    "tool": ToolListing,
    "skill": SkillListing,
    "hook": HookListing,
    "prompt": PromptListing,
    "sandbox": SandboxListing,
    "graphrag": GraphRagListing,
}


def _require_admin(user: User):
    if user.role != UserRole.admin:
        raise HTTPException(status_code=403, detail="Admin access required")


async def _find_listing(listing_id: str, db: AsyncSession):
    """Try each listing model to find the listing by id or unique prefix."""
    matches = []
    for listing_type, model in LISTING_MODELS.items():
        try:
            # First try exact/prefix using the helper
            listing = await resolve_prefix_id(model, listing_id, db)
            matches.append((listing_type, listing))
        except HTTPException as e:
            if e.status_code == 404:
                # Not found in this model, try by name as fallback for legacy
                from sqlalchemy import select
                result = await db.execute(select(model).where(model.name == listing_id))
                listing = result.scalar_one_or_none()
                if listing:
                    matches.append((listing_type, listing))
                continue
            # Rethrow 400 (Ambiguous) or other errors
            raise e

    if not matches:
        return None, None

    if len(matches) == 1:
        return matches[0]

    # Multiple models matched (cross-type ambiguity)
    detail = f"Ambiguous identifier '{listing_id}' matches multiple component types: "
    detail += ", ".join([f"{m[0]} ({str(m[1].id)[:8]}...)" for m in matches])
    raise HTTPException(status_code=400, detail=detail)


@router.get("")
async def list_pending(
    type: str | None = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _require_admin(current_user)

    models_to_query = {type: LISTING_MODELS[type]} if type and type in LISTING_MODELS else LISTING_MODELS
    items = []
    for listing_type, model in models_to_query.items():
        result = await db.execute(
            select(model).where(model.status == ListingStatus.pending).order_by(model.created_at.desc())
        )
        for r in result.scalars().all():
            items.append(
                {
                    "type": listing_type,
                    "id": str(r.id),
                    "name": r.name,
                    "status": r.status.value,
                    "submitted_by": str(r.submitted_by),
                    "created_at": r.created_at.isoformat(),
                }
            )
    return items


@router.get("/{listing_id}")
async def get_review(
    listing_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _require_admin(current_user)
    listing_type, listing = await _find_listing(listing_id, db)
    if not listing:
        raise HTTPException(status_code=404, detail="Listing not found")
    return {
        "type": listing_type,
        "id": str(listing.id),
        "name": listing.name,
        "status": listing.status.value,
        "submitted_by": str(listing.submitted_by),
        "created_at": listing.created_at.isoformat(),
    }


@router.post("/{listing_id}/approve")
async def approve(
    listing_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _require_admin(current_user)
    listing_type, listing = await _find_listing(listing_id, db)
    if not listing:
        raise HTTPException(status_code=404, detail="Listing not found")
    listing.status = ListingStatus.approved
    await db.commit()
    await db.refresh(listing)
    return {"type": listing_type, "id": str(listing.id), "name": listing.name, "status": listing.status.value}


@router.post("/{listing_id}/reject")
async def reject(
    listing_id: str,
    req: ReviewActionRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _require_admin(current_user)
    listing_type, listing = await _find_listing(listing_id, db)
    if not listing:
        raise HTTPException(status_code=404, detail="Listing not found")
    listing.status = ListingStatus.rejected
    listing.rejection_reason = req.reason
    await db.commit()
    await db.refresh(listing)
    return {"type": listing_type, "id": str(listing.id), "name": listing.name, "status": listing.status.value}
