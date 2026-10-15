# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Read-only, audience-limited companion API. No raw telemetry or inferred counts.

Every handler authenticates the mobile audience. The conservative unavailable
readings intentionally remain null until a qualified, retained and revocable
projection is available; registration or current status alone is not evidence.
"""

from datetime import UTC, datetime, timedelta
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

import services.dynamic_settings as ds
from api.deps import get_db, get_mobile_user
from models.mcp import McpListing
from models.user import User, UserRole
from observal_shared.migration.constants import DEFAULT_PROJECT_ID
from services.mobile_activity_query import qualified_components, qualified_observations
from services.mobile_general_sessions import prompted_roots

router = APIRouter(prefix="/api/v1/mobile-activity/v1", tags=["mobile-activity"])
Period = Literal["1w", "1m", "3m"]
Scope = Literal["user", "author"]
_DAYS = {"1w": 7, "1m": 30, "3m": 90}


class Coverage(BaseModel):
    eligible_sessions: int | None = None
    source_start: datetime | None = None
    source_end: datetime | None = None
    supported_harnesses: list[str] = Field(default_factory=list)
    projection: Literal["partial", "unavailable"] = "unavailable"


class Reading(BaseModel):
    value: int | None = None
    status: Literal["partial", "not_recorded"] = "not_recorded"
    reasons: list[str] = Field(default_factory=lambda: ["unavailable"])
    coverage: Coverage = Field(default_factory=Coverage)


class Window(BaseModel):
    start: datetime
    end: datetime
    as_of: datetime
    timezone: Literal["UTC"] = "UTC"
    period: Period


class PersonSummary(BaseModel):
    subject_id: UUID
    scope: Scope
    window: Window
    revision: str
    mcp_calls: Reading = Field(default_factory=Reading)
    confirmed_skill_loads: Reading = Field(default_factory=Reading)
    recorded_hook_runs: Reading = Field(default_factory=Reading)
    activity_traces: Reading = Field(default_factory=Reading)
    active_days_utc: Reading = Field(default_factory=Reading)
    general_sessions: Reading = Field(default_factory=Reading)


class PlatformOverview(BaseModel):
    window: Window
    revision: str
    active_accounts: Reading = Field(default_factory=Reading)
    prompted_root_sessions: Reading = Field(default_factory=Reading)


class Capabilities(BaseModel):
    contract: Literal["mobile-activity-v1"] = "mobile-activity-v1"
    server_id: UUID
    project_id: str
    viewer_id: UUID
    kinds: list[str] = Field(default_factory=list)
    platform_overview: bool


class PublicPerson(BaseModel):
    id: UUID
    username: str
    name: str


class PeoplePage(BaseModel):
    items: list[PublicPerson]
    complete: Literal[False] = False  # No cursor; never imply a complete directory.


class SummaryBatch(BaseModel):
    items: list[PersonSummary]


class ComponentObservation(BaseModel):
    kind: Literal["mcp"] = "mcp"
    component_id: UUID
    name: str
    mcp_calls: Reading
    activity_traces: Reading
    active_days_utc: Reading


class ComponentPage(BaseModel):
    subject_id: UUID
    scope: Scope
    window: Window
    revision: str
    items: list[ComponentObservation] = Field(default_factory=list)
    complete: Literal[False] = False  # No stable cursor yet.


class ComponentDetail(BaseModel):
    subject_id: UUID
    scope: Scope
    window: Window
    revision: str
    component: ComponentObservation


class PublishedItem(BaseModel):
    kind: str
    id: UUID
    name: str
    namespace: str
    slug: str
    is_current_owner: bool


class PublishedPage(BaseModel):
    items: list[PublishedItem]
    complete: Literal[False] = False  # Bounded first slice only, no unsafe offset cursor.


def _window(period: Period, *, platform: bool = False) -> Window:
    now = datetime.now(UTC)
    end = now.replace(hour=0, minute=0, second=0, microsecond=0) if platform else now
    return Window(start=end - timedelta(days=_DAYS[period]), end=end, as_of=now, period=period)


def _can_trace(viewer: User, trace_privacy: bool) -> bool:
    return viewer.role == UserRole.super_admin or (viewer.role == UserRole.admin and not trace_privacy)


async def _trace_allowed(viewer: User) -> bool:
    return _can_trace(viewer, await ds.get_bool("security.trace_privacy"))


async def _subject(db: AsyncSession, subject_id: UUID) -> User:
    subject = await db.scalar(select(User).where(User.id == subject_id, User.auth_provider != "deactivated"))
    if subject is None:
        raise HTTPException(status_code=404, detail="Not found")
    return subject


async def _authorize(viewer: User, subject_id: UUID, scope: Scope, db: AsyncSession) -> None:
    # Do not reveal whether a different subject exists to unauthorized viewers.
    if (scope == "author" or subject_id != viewer.id) and not await _trace_allowed(viewer):
        raise HTTPException(status_code=403, detail="Restricted")
    await _subject(db, subject_id)


def _partial(value: int, eligible_sessions: int) -> Reading:
    return Reading(
        value=value,
        status="partial",
        reasons=["observed_qualified_only", "incomplete_coverage"],
        coverage=Coverage(eligible_sessions=eligible_sessions, supported_harnesses=["pi"], projection="partial"),
    )


def _component(component_id: UUID, name: str, observed: dict) -> ComponentObservation:
    return ComponentObservation(
        component_id=component_id,
        name=name,
        mcp_calls=_partial(observed["calls"], observed["eligible_sessions"]),
        activity_traces=_partial(observed["roots"], observed["eligible_sessions"]) if observed["roots"] else Reading(),
        active_days_utc=_partial(observed["days"], observed["eligible_sessions"]) if observed["days"] else Reading(),
    )


async def _summary(subject_id: UUID, scope: Scope, period: Period, db: AsyncSession) -> PersonSummary:
    # Revision does not promise a frozen snapshot; every read revalidates the
    # source and visibility. The UI must refetch on focus/permission changes.
    summary = PersonSummary(subject_id=subject_id, scope=scope, window=_window(period), revision="unqualified")
    if scope == "user":
        general = await prompted_roots(
            db, str(DEFAULT_PROJECT_ID), summary.window.start, summary.window.end, subject=subject_id
        )
        if general:
            summary.revision = "observed-partial"
            summary.general_sessions = Reading(
                value=general["roots"],
                status="partial",
                reasons=["observed_prompted_roots", "incomplete_coverage"],
                coverage=Coverage(
                    eligible_sessions=general["eligible_sessions"], supported_harnesses=["pi"], projection="partial"
                ),
            )
    observed = await qualified_observations(
        db, subject_id, scope, str(DEFAULT_PROJECT_ID), summary.window.start, summary.window.end
    )
    if observed is None:
        return summary
    # Positive lower bounds only. No supported zero, complete-window claim or
    # unsupported skill/hook/general-session extrapolation from MCP calls.
    summary.mcp_calls = _partial(observed["calls"], observed["eligible_sessions"])
    if observed["roots"]:
        summary.activity_traces = _partial(observed["roots"], observed["eligible_sessions"])
    if observed["days"]:
        summary.active_days_utc = _partial(observed["days"], observed["eligible_sessions"])
    summary.revision = "observed-partial"
    return summary


@router.get("/capabilities", response_model=Capabilities)
async def capabilities(db: AsyncSession = Depends(get_db), viewer: User = Depends(get_mobile_user)):
    server_id = await db.scalar(text("SELECT server_id FROM mobile_server_identity WHERE singleton = true"))
    if server_id is None:
        raise HTTPException(status_code=503, detail="Server identity unavailable")
    return Capabilities(
        server_id=server_id,
        project_id=str(DEFAULT_PROJECT_ID),
        viewer_id=viewer.id,
        kinds=[],  # Not advertised until evidence + sender cohort is qualified.
        platform_overview=await _trace_allowed(viewer),
    )


@router.get("/platform/overview", response_model=PlatformOverview)
async def platform_overview(
    period: Period, db: AsyncSession = Depends(get_db), viewer: User = Depends(get_mobile_user)
):
    if not await _trace_allowed(viewer):
        raise HTTPException(status_code=403, detail="Restricted")
    result = PlatformOverview(window=_window(period, platform=True), revision="unqualified")
    general = await prompted_roots(db, str(DEFAULT_PROJECT_ID), result.window.start, result.window.end)
    if general is None or general["active_accounts"] < 10:
        return result  # Same redacted shape for suppressed, purged, unsupported.
    coverage = Coverage(
        eligible_sessions=general["eligible_sessions"], supported_harnesses=["pi"], projection="partial"
    )
    result.active_accounts = Reading(
        value=general["active_accounts"],
        status="partial",
        reasons=["observed_prompted_roots", "incomplete_coverage"],
        coverage=coverage,
    )
    result.prompted_root_sessions = Reading(
        value=general["roots"],
        status="partial",
        reasons=["observed_prompted_roots", "incomplete_coverage"],
        coverage=coverage,
    )
    result.revision = "observed-partial"
    return result


@router.get("/people/{subject_id}/summary", response_model=PersonSummary)
async def person_summary(
    subject_id: UUID,
    scope: Scope,
    period: Period,
    db: AsyncSession = Depends(get_db),
    viewer: User = Depends(get_mobile_user),
):
    await _authorize(viewer, subject_id, scope, db)
    return await _summary(subject_id, scope, period, db)


@router.post("/people/summaries", response_model=SummaryBatch)
async def person_summaries(
    subject_ids: list[UUID],
    scope: Scope,
    period: Period,
    db: AsyncSession = Depends(get_db),
    viewer: User = Depends(get_mobile_user),
):
    if not subject_ids or len(subject_ids) > 5 or len(set(subject_ids)) != len(subject_ids):
        raise HTTPException(status_code=422, detail="One to five distinct subjects required")
    if (scope == "author" or any(subject_id != viewer.id for subject_id in subject_ids)) and not await _trace_allowed(
        viewer
    ):
        raise HTTPException(status_code=403, detail="Restricted")
    rows = await db.scalars(select(User.id).where(User.id.in_(subject_ids), User.auth_provider != "deactivated"))
    if set(rows.all()) != set(subject_ids):
        raise HTTPException(status_code=404, detail="Not found")
    return SummaryBatch(items=[await _summary(subject_id, scope, period, db) for subject_id in subject_ids])


@router.get("/people", response_model=PeoplePage)
async def people_search(
    q: str = Query(min_length=3, max_length=64),
    limit: int = Query(20, ge=1, le=20),
    db: AsyncSession = Depends(get_db),
    viewer: User = Depends(get_mobile_user),
):
    del viewer
    term = q.strip()
    if len(term) < 3:
        raise HTTPException(status_code=422, detail="Search term too short")
    # Literal prefix, no email/role search. Index-friendly for a bounded first page.
    pattern = term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
    rows = await db.scalars(
        select(User)
        .where(
            User.auth_provider != "deactivated",
            (User.username.ilike(pattern, escape="\\") | User.name.ilike(pattern, escape="\\")),
        )
        .order_by(User.username, User.id)
        .limit(limit)
    )
    return PeoplePage(items=[PublicPerson.model_validate(row, from_attributes=True) for row in rows.all()])


@router.get("/people/{subject_id}/{scope}/components", response_model=ComponentPage)
async def components(
    subject_id: UUID,
    scope: Scope,
    period: Period,
    db: AsyncSession = Depends(get_db),
    viewer: User = Depends(get_mobile_user),
):
    await _authorize(viewer, subject_id, scope, db)
    window = _window(period)
    rows = await qualified_components(db, subject_id, scope, str(DEFAULT_PROJECT_ID), window.start, window.end)
    if rows is None:
        return ComponentPage(subject_id=subject_id, scope=scope, window=window, revision="unqualified")
    return ComponentPage(
        subject_id=subject_id,
        scope=scope,
        window=window,
        revision="observed-partial",
        items=[_component(row["id"], row["name"], row) for row in rows],
    )


@router.get("/people/{subject_id}/{scope}/components/{kind}/{component_id}", response_model=ComponentDetail)
async def component_detail(
    subject_id: UUID,
    scope: Scope,
    kind: Literal["mcp", "skill", "hook"],
    component_id: UUID,
    period: Period,
    db: AsyncSession = Depends(get_db),
    viewer: User = Depends(get_mobile_user),
):
    await _authorize(viewer, subject_id, scope, db)
    if kind != "mcp":
        raise HTTPException(status_code=404, detail="Not found")
    window = _window(period)
    observed = await qualified_observations(
        db, subject_id, scope, str(DEFAULT_PROJECT_ID), window.start, window.end, component_id
    )
    if observed is None:
        raise HTTPException(status_code=404, detail="Not found")
    listing = await db.scalar(select(McpListing).where(McpListing.id == component_id, McpListing.is_private.is_(False)))
    if listing is None:
        raise HTTPException(status_code=404, detail="Not found")
    return ComponentDetail(
        subject_id=subject_id,
        scope=scope,
        window=window,
        revision="observed-partial",
        component=_component(listing.id, listing.name, observed),
    )


# Static table names only; caller cannot supply identifiers or SQL fragments.
_PUBLISHED = (
    ("mcp", "mcp_listings", "mcp_versions", "listing_id"),
    ("skill", "skill_listings", "skill_versions", "listing_id"),
    ("hook", "hook_listings", "hook_versions", "listing_id"),
    ("prompt", "prompt_listings", "prompt_versions", "listing_id"),
    ("sandbox", "sandbox_listings", "sandbox_versions", "listing_id"),
    ("agent", "agents", "agent_versions", "agent_id"),
)


@router.get("/published", response_model=PublishedPage)
async def published_by_me(
    limit: int = Query(20, ge=1, le=20),
    db: AsyncSession = Depends(get_db),
    viewer: User = Depends(get_mobile_user),
):
    branches = []
    for kind, listing, version, version_fk in _PUBLISHED:
        current_owner = "created_by" if kind == "agent" else "submitted_by"
        deleted = "AND l.deleted_at IS NULL" if kind == "agent" else ""
        branches.append(
            f"SELECT '{kind}' AS kind, l.id, l.name, l.namespace, l.slug, "
            f"(l.{current_owner} = :viewer) AS is_current_owner "
            f"FROM mobile_listing_provenance p JOIN {listing} l ON l.id = p.listing_id "
            f"WHERE p.kind = '{kind}' AND p.original_author_id = :viewer "
            f"AND l.is_private = false {deleted} "
            f"AND EXISTS (SELECT 1 FROM {version} v JOIN mobile_publication_events e "
            f"ON e.kind = '{kind}' AND e.listing_id = l.id "
            f"AND e.version_id = v.id AND e.status = 'approved' "
            f"WHERE v.{version_fk} = l.id AND v.status = 'approved')"
        )
    # UNION ALL is bounded by the indexed provenance author key. No total or
    # unsafe offset pagination; caller knows the first slice is incomplete.
    sql = "SELECT * FROM (" + " UNION ALL ".join(branches) + ") published ORDER BY kind, id LIMIT :limit"
    rows = (await db.execute(text(sql), {"viewer": viewer.id, "limit": limit})).mappings().all()
    return PublishedPage(items=[PublishedItem.model_validate(row) for row in rows])
