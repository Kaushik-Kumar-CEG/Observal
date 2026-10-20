# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Read-only, audience-limited companion API. No raw telemetry or inferred counts.

Every handler authenticates the mobile audience. The conservative unavailable
readings intentionally remain null until a qualified, retained and revocable
projection is available; registration or current status alone is not evidence.
"""

import hashlib
import hmac
import json
from datetime import UTC, datetime, timedelta
from typing import Literal
from uuid import UUID

import jwt
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel, Field
from sqlalchemy import and_, or_, select, text
from sqlalchemy.ext.asyncio import AsyncSession

import services.dynamic_settings as ds
from api.deps import get_db, get_mobile_user
from models.user import User, UserRole
from observal_shared.migration.constants import DEFAULT_PROJECT_ID
from services.crypto import get_key_manager, sign_token, verify_token
from services.mobile_activity_query import qualified_zero_subset, trace_component_page, trace_pair_batch, trace_union
from services.mobile_general_sessions import prompted_roots
from services.mobile_read_control import active_mobile_cohort, readable

router = APIRouter(prefix="/api/v1/mobile-activity/v1", tags=["mobile-activity"])
Period = Literal["1w", "1m", "3m"]
Scope = Literal["user", "author"]
_DAYS = {"1w": 7, "1m": 30, "3m": 90}


class Coverage(BaseModel):
    eligible_sessions: int | None = None
    source_start: datetime | None = None
    source_end: datetime | None = None
    supported_harnesses: list[str] = Field(default_factory=list)
    supported_kinds: list[str] = Field(default_factory=list)
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
    window_anchor: str
    revision: str
    component_trace_union: Reading = Field(default_factory=Reading)
    mcp_calls: Reading = Field(default_factory=Reading)
    confirmed_skill_loads: Reading = Field(default_factory=Reading)
    recorded_hook_runs: Reading = Field(default_factory=Reading)
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
    supported_kinds: list[str] = Field(default_factory=list)
    platform_overview: bool
    trace_headlines: bool = False
    synthetic_test_cohort: bool = False


class PublicPerson(BaseModel):
    id: UUID
    username: str
    name: str


class PeoplePage(BaseModel):
    items: list[PublicPerson]
    complete: bool
    next_cursor: str | None = None


class ResolveRequest(BaseModel):
    subject_ids: list[UUID] = Field(min_length=1, max_length=20)


class PairedRequest(BaseModel):
    subject_ids: list[UUID] = Field(min_length=1, max_length=12)
    period: Period
    window_anchor: str | None = Field(None, max_length=512)


class RestrictedScope(BaseModel):
    # Explicit denial, not Not recorded: never include a value, source or cohort.
    status: Literal["restricted"] = "restricted"


class PairedPerson(BaseModel):
    subject_id: UUID
    author_revision: str
    user_revision: str
    author_usage: Reading | RestrictedScope = Field(default_factory=Reading)
    user_usage: Reading | RestrictedScope = Field(default_factory=Reading)


class PairedBatch(BaseModel):
    window: Window
    window_anchor: str
    items: list[PairedPerson]


class ComponentObservation(BaseModel):
    kind: Literal["mcp", "skill", "hook"] = "mcp"
    component_id: UUID
    name: str
    author: PublicPerson
    component_traces: Reading
    mcp_calls: Reading
    confirmed_skill_loads: Reading = Field(default_factory=Reading)
    recorded_hook_runs: Reading = Field(default_factory=Reading)


class ComponentPage(BaseModel):
    subject_id: UUID
    scope: Scope
    window: Window
    window_anchor: str
    revision: str
    items: list[ComponentObservation] = Field(default_factory=list)
    complete: bool = False
    next_cursor: str | None = None


class ComponentDetail(BaseModel):
    subject_id: UUID
    scope: Scope
    window: Window
    window_anchor: str
    revision: str
    component: ComponentObservation


class PublishedItem(BaseModel):
    kind: str
    id: UUID
    name: str
    is_current_owner: bool


class PublishedPage(BaseModel):
    items: list[PublishedItem]
    complete: bool
    next_cursor: str | None = None


def _window(period: Period, *, platform: bool = False) -> Window:
    now = datetime.now(UTC)
    end = now.replace(hour=0, minute=0, second=0, microsecond=0) if platform else now
    return Window(start=end - timedelta(days=_DAYS[period]), end=end, as_of=now, period=period)


def _paired_window(viewer: User, period: Period, anchor: str | None) -> tuple[Window, str]:
    if anchor is None:
        window = _window(period)
        issued = int(window.as_of.timestamp())
        token = sign_token(
            {
                "purpose": "mobile-paired-window-v1",
                "sub": str(viewer.id),
                "project": str(DEFAULT_PROJECT_ID),
                "period": period,
                "end": window.end.isoformat(),
                "iat": issued,
                "exp": issued + 900,
            }
        )
        if len(token) > 512:
            raise HTTPException(status_code=503, detail="Window anchor unavailable")
        return window, token
    try:
        claims = verify_token(anchor)
        if (
            claims.get("purpose") != "mobile-paired-window-v1"
            or claims.get("sub") != str(viewer.id)
            or claims.get("project") != str(DEFAULT_PROJECT_ID)
            or claims.get("period") != period
        ):
            raise ValueError("window scope mismatch")
        end = datetime.fromisoformat(claims["end"])
        if end.tzinfo is None:
            raise ValueError("window timezone missing")
        # iat has whole-second precision but the signed end retains
        # microseconds. Reconstruct as_of from that exact end, or the phone
        # correctly rejects end > as_of on every anchored detail/page.
        if int(end.timestamp()) != claims["iat"]:
            raise ValueError("window issue/end mismatch")
        return Window(start=end - timedelta(days=_DAYS[period]), end=end, as_of=end, period=period), anchor
    except (ValueError, TypeError, KeyError, jwt.InvalidTokenError) as exc:
        raise HTTPException(status_code=409, detail="stale_window") from exc


async def _scope_revision(db: AsyncSession, viewer: User, subject: UUID, scope: Scope, anchor: str) -> str:
    epoch = (
        await db.scalar(
            text(
                "SELECT epoch FROM mobile_scope_epochs WHERE project_id=:project AND subject_id=:subject AND scope=:scope"
            ),
            {"project": str(DEFAULT_PROJECT_ID), "subject": subject, "scope": scope},
        )
        or 0
    )
    generation = (
        await db.scalar(
            text("SELECT generation FROM mobile_read_controls WHERE project_id=:project"),
            {"project": str(DEFAULT_PROJECT_ID)},
        )
        or 0
    )
    # Indexed clock frontier: an ancestor's TTL passing causes the next
    # deadline to change even without a worker write. Author links are
    # precomputed on typed fact insert (including retained-data upgrade),
    # so there is no recursive ancestry scan on live card/page/detail reads.
    if scope == "user":
        deadline_sql = text(
            "SELECT source_retained_until FROM mobile_session_publications "
            "WHERE project_id=:project AND user_id=:subject AND source_retained_until>clock_timestamp() "
            "AND status IN ('complete','partial') AND source_policy_epoch=(SELECT source_policy_epoch "
            "FROM mobile_read_controls WHERE project_id=:project) ORDER BY source_retained_until LIMIT 1"
        )
    else:
        deadline_sql = text(
            "SELECT MIN(next_source.source_retained_until) FROM mobile_author_actor_links link "
            "JOIN LATERAL (SELECT source_retained_until FROM mobile_session_publications pub "
            "WHERE pub.project_id=link.project_id AND pub.user_id=link.actor_id "
            "AND pub.source_retained_until>clock_timestamp() AND pub.status IN ('complete','partial') "
            "AND pub.source_policy_epoch=(SELECT source_policy_epoch FROM mobile_read_controls "
            "WHERE project_id=:project) "
            "ORDER BY pub.source_retained_until LIMIT 1) next_source ON true "
            "WHERE link.project_id=:project AND link.author_id=:subject"
        )
    deadline = await db.scalar(deadline_sql, {"project": str(DEFAULT_PROJECT_ID), "subject": subject})
    return _sign_scope_revision(viewer, subject, scope, anchor, generation, epoch, deadline)


def _sign_scope_revision(
    viewer: User,
    subject: UUID,
    scope: Scope,
    anchor: str,
    generation: int,
    epoch: int,
    deadline: datetime | None,
    private_key: bytes | None = None,
) -> str:
    # Revision is opaque to the phone. MAC ALL dimensions with the current
    # server signing key: ECDSA signatures are randomized, so re-signing the
    # same claims on a detail request never equals the paired-card revision.
    # A fixed-size MAC fits the accepted query bound and cannot be guessed
    # without the server key. Key rotation correctly invalidates old cursors.
    fingerprint = hashlib.sha256(
        json.dumps(
            [
                str(viewer.id),
                str(subject),
                scope,
                str(DEFAULT_PROJECT_ID),
                anchor,
                generation,
                epoch,
                deadline.isoformat() if deadline is not None else None,
            ],
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    if private_key is None:
        private_key = (
            get_key_manager().get_private_key().private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())
        )
    return "r2_" + hmac.new(private_key, fingerprint.encode(), hashlib.sha256).hexdigest()


async def _scope_revisions(db: AsyncSession, viewer: User, subjects: list[tuple[UUID, Scope]], anchor: str) -> dict:
    """One indexed PostgreSQL snapshot for the bounded 12-person paired viewport."""
    if not subjects:
        return {}
    if len(subjects) > 24:
        raise ValueError("Too many mobile revision scopes")
    rows = (
        (
            await db.execute(
                text("""
            WITH requested AS (
              SELECT unnest(CAST(:subject_ids AS uuid[])) AS subject_id,
                     unnest(CAST(:scopes AS text[])) AS scope
            )
            SELECT requested.subject_id,requested.scope,coalesce(e.epoch,0) AS epoch,
              coalesce(g.generation,0) AS generation,
              CASE WHEN requested.scope='user' THEN user_deadline.floor ELSE author_deadline.floor END AS deadline
            FROM requested
            LEFT JOIN mobile_scope_epochs e ON e.project_id=:project
              AND e.subject_id=requested.subject_id AND e.scope=requested.scope
            LEFT JOIN mobile_read_controls g ON g.project_id=:project
            LEFT JOIN LATERAL (
              SELECT pub.source_retained_until AS floor FROM mobile_session_publications pub
              WHERE requested.scope='user' AND pub.project_id=:project AND pub.user_id=requested.subject_id
                AND pub.status IN ('complete','partial') AND pub.source_retained_until>clock_timestamp()
                AND pub.source_policy_epoch=g.source_policy_epoch
              ORDER BY pub.source_retained_until LIMIT 1
            ) user_deadline ON true
            LEFT JOIN LATERAL (
              SELECT min(next_source.floor) AS floor FROM mobile_author_actor_links link
              JOIN LATERAL (
                SELECT pub.source_retained_until AS floor FROM mobile_session_publications pub
                WHERE pub.project_id=link.project_id AND pub.user_id=link.actor_id
                  AND pub.status IN ('complete','partial') AND pub.source_retained_until>clock_timestamp()
                  AND pub.source_policy_epoch=g.source_policy_epoch
                ORDER BY pub.source_retained_until LIMIT 1
              ) next_source ON true
              WHERE requested.scope='author' AND link.project_id=:project
                AND link.author_id=requested.subject_id
            ) author_deadline ON true
        """),
                {
                    "project": str(DEFAULT_PROJECT_ID),
                    "subject_ids": [subject for subject, _ in subjects],
                    "scopes": [scope for _, scope in subjects],
                },
            )
        )
        .mappings()
        .all()
    )
    private_key = get_key_manager().get_private_key().private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())
    return {
        (row.subject_id, row.scope): _sign_scope_revision(
            viewer, row.subject_id, row.scope, anchor, row.generation, row.epoch, row.deadline, private_key
        )
        for row in rows
    }


def _can_trace(viewer: User, trace_privacy: bool) -> bool:
    return viewer.role == UserRole.super_admin or (viewer.role == UserRole.admin and not trace_privacy)


async def _trace_allowed(viewer: User) -> bool:
    return _can_trace(viewer, await ds.get_bool("security.trace_privacy"))


async def _subject(db: AsyncSession, subject_id: UUID) -> User:
    subject = await db.scalar(select(User).where(User.id == subject_id, User.auth_provider != "deactivated"))
    if subject is None:
        raise HTTPException(status_code=404, detail="Not found")
    return subject


async def _synthetic_subjects(db: AsyncSession, viewer: User) -> set[UUID] | None:
    """Synthetic viewers may name only the two disposable cohort principals."""
    # The route dependency denies unqualified viewers; live paths need no
    # synthetic lookup when the isolated cohort switch is off.
    if await ds.get("mobile.synthetic_test_enabled") != "true":
        return None
    cohort = await active_mobile_cohort(db, viewer)
    if cohort == "live":
        return None
    if cohort not in ("synthetic-author", "synthetic-user"):
        return set()
    try:
        return {
            UUID(await ds.get("mobile.synthetic_test_viewer_id")),
            UUID(await ds.get("mobile.synthetic_test_self_user_viewer_id")),
        }
    except (ValueError, TypeError):
        return set()


async def _authorize(viewer: User, subject_id: UUID, scope: Scope, db: AsyncSession) -> bool:
    # Do not reveal whether a different subject exists to unauthorized viewers.
    subjects = await _synthetic_subjects(db, viewer)
    if subjects is not None and subject_id not in subjects:
        return False
    # The ordinary actor must not gain foreign or Author readings even when
    # temporarily granted an admin role to review the other account's listings.
    privileged = await _trace_allowed(viewer)
    if await ds.get("mobile.synthetic_test_enabled") == "true":
        privileged = (await active_mobile_cohort(db, viewer)) == "synthetic-author"
    if (scope == "author" or subject_id != viewer.id) and not privileged:
        return False
    await _subject(db, subject_id)
    return True


def _partial(value: int, eligible_sessions: int | None = None, *, kinds: list[str] | None = None) -> Reading:
    return Reading(
        value=value,
        status="partial",
        reasons=["observed_qualified_only", "incomplete_coverage"],
        coverage=Coverage(
            eligible_sessions=eligible_sessions,
            supported_harnesses=["pi"],
            supported_kinds=kinds if kinds is not None else ["mcp_calls"],
            projection="partial",
        ),
    )


def _observed_kinds(observed: dict) -> list[str]:
    kinds = ["mcp_calls"] if observed.get("calls", 0) or observed.get("eligible_sessions") else []
    if observed.get("skill_loads", 0):
        kinds.append("confirmed_skill_loads")
    if observed.get("hook_runs", 0):
        kinds.append("recorded_hook_runs")
    return kinds


def _component(observed: dict) -> ComponentObservation:
    kind = observed.get("kind", "mcp")
    supported = {"mcp": ["mcp_calls"], "skill": ["confirmed_skill_loads"], "hook": ["recorded_hook_runs"]}[kind]
    return ComponentObservation(
        kind=kind,
        component_id=observed["id"],
        name=observed["name"],
        author=PublicPerson(
            id=observed["original_author_id"], username=observed["author_username"], name=observed["author_name"]
        ),
        component_traces=_partial(observed["roots"], kinds=supported),
        mcp_calls=_partial(observed["calls"]) if kind == "mcp" else Reading(),
        confirmed_skill_loads=_partial(observed["skill_loads"], kinds=supported) if kind == "skill" else Reading(),
        recorded_hook_runs=_partial(observed["hook_runs"], kinds=supported) if kind == "hook" else Reading(),
    )


async def _summary(
    subject_id: UUID,
    scope: Scope,
    period: Period,
    db: AsyncSession,
    viewer: User,
    anchor: str | None = None,
) -> PersonSummary:
    window, token = _paired_window(viewer, period, anchor)
    if not await readable(db, str(DEFAULT_PROJECT_ID)):
        return PersonSummary(
            subject_id=subject_id, scope=scope, window=window, window_anchor=token, revision="unqualified"
        )
    summary = PersonSummary(
        subject_id=subject_id,
        scope=scope,
        window=window,
        window_anchor=token,
        revision=await _scope_revision(db, viewer, subject_id, scope, token),
    )
    if scope == "user":
        general = await prompted_roots(db, str(DEFAULT_PROJECT_ID), window.start, window.end, subject=subject_id)
        if general:
            summary.general_sessions = Reading(
                value=general["roots"],
                status="partial",
                reasons=["observed_prompted_roots", "incomplete_coverage"],
                coverage=Coverage(
                    eligible_sessions=general["eligible_sessions"], supported_harnesses=["pi"], projection="partial"
                ),
            )
    observed = await trace_union(
        db,
        subject_id,
        scope,
        str(DEFAULT_PROJECT_ID),
        window.start,
        window.end,
        viewer_self=viewer.id == subject_id,
        actor_ids=await _synthetic_subjects(db, viewer),
    )
    if observed:
        kinds = _observed_kinds(observed)
        summary.component_trace_union = _partial(observed["roots"], kinds=kinds)
        if observed["calls"]:
            summary.mcp_calls = _partial(observed["calls"])
        if observed.get("skill_loads", 0):
            summary.confirmed_skill_loads = _partial(observed["skill_loads"], kinds=["confirmed_skill_loads"])
        if observed.get("hook_runs", 0):
            summary.recorded_hook_runs = _partial(observed["hook_runs"], kinds=["recorded_hook_runs"])
        summary.active_days_utc = _partial(observed["days"], kinds=kinds)
    elif scope == "user" and viewer.id == subject_id:
        zero = await qualified_zero_subset(db, subject_id, str(DEFAULT_PROJECT_ID), window.start, window.end)
        if zero:
            summary.component_trace_union = _partial(0, zero["eligible_sessions"])
            summary.mcp_calls = _partial(0, zero["eligible_sessions"])
            summary.active_days_utc = _partial(0, zero["eligible_sessions"])
    if await _scope_revision(db, viewer, subject_id, scope, token) != summary.revision:
        raise HTTPException(409, "stale_cursor")
    return summary


@router.get("/capabilities", response_model=Capabilities)
async def capabilities(db: AsyncSession = Depends(get_db), viewer: User = Depends(get_mobile_user)):
    server_id = await db.scalar(text("SELECT server_id FROM mobile_server_identity WHERE singleton = true"))
    if server_id is None:
        raise HTTPException(status_code=503, detail="Server identity unavailable")
    # The exact same barrier-bound cohort decision guards every data route.
    cohort = await active_mobile_cohort(db, viewer, server_id=str(server_id))
    live = cohort == "live"
    author_viewer = cohort == "synthetic-author"
    test_only = cohort in ("synthetic-author", "synthetic-user")
    kinds: list[str] = []
    if test_only:
        # The capability covers every authorized 1W/1M/3M reading, not just
        # the current week. Use the longest accepted window with the same
        # subject, scope and disposable actor allowlist as the data route;
        # do not advertise a kind from another person's private activity.
        window = _window("3m")
        observed = await trace_union(
            db,
            viewer.id,
            "author" if author_viewer else "user",
            str(DEFAULT_PROJECT_ID),
            window.start,
            window.end,
            viewer_self=True,
            actor_ids=await _synthetic_subjects(db, viewer),
        )
        if observed and observed["roots"] > 0:
            kinds = [
                kind
                for key, kind in (
                    ("calls", "mcp_calls"),
                    ("skill_loads", "confirmed_skill_loads"),
                    ("hook_runs", "recorded_hook_runs"),
                )
                if observed.get(key, 0) > 0
            ]
        test_only = bool(kinds)
    return Capabilities(
        server_id=server_id,
        project_id=str(DEFAULT_PROJECT_ID),
        viewer_id=viewer.id,
        # Production is all-kind only after the owner qualifies all three
        # positive evidence paths; unsupported zeros remain Not recorded.
        supported_kinds=["mcp_calls", "confirmed_skill_loads", "recorded_hook_runs"] if live else kinds,
        platform_overview=live and await _trace_allowed(viewer),
        trace_headlines=live,
        synthetic_test_cohort=test_only,
    )


@router.get("/platform/overview", response_model=PlatformOverview)
async def platform_overview(
    period: Period, db: AsyncSession = Depends(get_db), viewer: User = Depends(get_mobile_user)
):
    # Synthetic cohorts must not expose global measurements from other accounts.
    if await _synthetic_subjects(db, viewer) is not None or not await _trace_allowed(viewer):
        return Response(status_code=403)
    result = PlatformOverview(window=_window(period, platform=True), revision="unqualified")
    if not await readable(db, str(DEFAULT_PROJECT_ID)):
        return result
    general = await prompted_roots(db, str(DEFAULT_PROJECT_ID), result.window.start, result.window.end)
    if general is None or general["active_accounts"] < 10 or not await readable(db, str(DEFAULT_PROJECT_ID)):
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
    window_anchor: str | None = Query(None, max_length=512),
    db: AsyncSession = Depends(get_db),
    viewer: User = Depends(get_mobile_user),
):
    if not await _authorize(viewer, subject_id, scope, db):
        return Response(status_code=403)
    return await _summary(subject_id, scope, period, db, viewer, window_anchor)


@router.post("/people/summaries", response_model=PairedBatch)
async def person_summaries(
    request: PairedRequest,
    db: AsyncSession = Depends(get_db),
    viewer: User = Depends(get_mobile_user),
):
    subject_ids = request.subject_ids
    if len(set(subject_ids)) != len(subject_ids):
        raise HTTPException(status_code=422, detail="Distinct subjects required")
    subjects = await _synthetic_subjects(db, viewer)
    if subjects is not None and any(subject_id not in subjects for subject_id in subject_ids):
        return Response(status_code=403)
    privileged = await _trace_allowed(viewer)
    if await ds.get("mobile.synthetic_test_enabled") == "true":
        privileged = (await active_mobile_cohort(db, viewer)) == "synthetic-author"
    if not privileged and viewer.id not in subject_ids:
        return Response(status_code=403)
    if privileged:
        rows = await db.scalars(select(User.id).where(User.id.in_(subject_ids), User.auth_provider != "deactivated"))
        if set(rows.all()) != set(subject_ids):
            raise HTTPException(status_code=404, detail="Not found")
    window, anchor = _paired_window(viewer, request.period, request.window_anchor)
    # The paired self-zero fallback must not bypass the shared project read
    # barrier while retention/erasure is in progress. Do this before ANY
    # source-derived value, cohort, or scope revision is returned.
    if not await readable(db, str(DEFAULT_PROJECT_ID)):
        return PairedBatch(
            window=window,
            window_anchor=anchor,
            items=[
                PairedPerson(
                    subject_id=subject_id,
                    author_revision="unqualified" if privileged else "restricted",
                    user_revision="unqualified" if privileged or subject_id == viewer.id else "restricted",
                    author_usage=Reading() if privileged else RestrictedScope(),
                    user_usage=Reading() if privileged or subject_id == viewer.id else RestrictedScope(),
                )
                for subject_id in subject_ids
            ],
        )
    # Never look up other people's existence or facts for an unprivileged
    # mixed batch; the neutral status is identical for absent and forbidden IDs.
    permitted_ids = subject_ids if privileged else [viewer.id]
    scoped_subjects = [
        (subject_id, scope)
        for subject_id in permitted_ids
        for scope in (("author", "user") if privileged else ("user",))
    ]
    revisions_before = await _scope_revisions(db, viewer, scoped_subjects, anchor)
    authors, users = await trace_pair_batch(
        db,
        permitted_ids,
        viewer.id,
        str(DEFAULT_PROJECT_ID),
        window.start,
        window.end,
        include_author=privileged,
        actor_ids=subjects,
    )
    items = []
    for subject_id in subject_ids:
        if not privileged and subject_id != viewer.id:
            items.append(
                PairedPerson(
                    subject_id=subject_id,
                    author_revision="restricted",
                    user_revision="restricted",
                    author_usage=RestrictedScope(),
                    user_usage=RestrictedScope(),
                )
            )
            continue
        author, user = authors.get(subject_id), users.get(subject_id)
        if user is None and subject_id == viewer.id:
            user = await qualified_zero_subset(db, subject_id, str(DEFAULT_PROJECT_ID), window.start, window.end)
        items.append(
            PairedPerson(
                subject_id=subject_id,
                author_revision=revisions_before[subject_id, "author"] if privileged else "restricted",
                user_revision=revisions_before[subject_id, "user"],
                author_usage=(_partial(author["roots"], kinds=_observed_kinds(author)) if author else Reading())
                if privileged
                else RestrictedScope(),
                user_usage=_partial(user["roots"], user.get("eligible_sessions"), kinds=_observed_kinds(user))
                if user
                else Reading(),
            )
        )
    revisions_after = await _scope_revisions(db, viewer, scoped_subjects, anchor)
    if revisions_after != revisions_before:
        raise HTTPException(409, "stale_cursor")
    return PairedBatch(window=window, window_anchor=anchor, items=items)


def _cursor(claims: dict) -> str:
    token = sign_token({"purpose": "mobile-page-v1", "project": str(DEFAULT_PROJECT_ID), **claims})
    if len(token) > 512:
        raise HTTPException(503, "Cursor unavailable")
    return token


def _read_cursor(token: str, expected: dict) -> dict:
    try:
        claims = verify_token(token)
        if any(claims.get(key) != value for key, value in expected.items()):
            raise ValueError("cursor scope changed")
        return claims
    except (ValueError, TypeError, jwt.InvalidTokenError) as exc:
        raise HTTPException(409, "stale_cursor") from exc


@router.get("/people", response_model=PeoplePage)
async def people_search(
    q: str = Query(min_length=3, max_length=64),
    limit: int = Query(20, ge=1, le=20),
    cursor: str | None = Query(None, max_length=512),
    db: AsyncSession = Depends(get_db),
    viewer: User = Depends(get_mobile_user),
):
    term = q.strip()
    if len(term) < 3:
        raise HTTPException(status_code=422, detail="Search term too short")
    pattern = term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
    key = {
        "sub": str(viewer.id),
        "q": hashlib.sha256(term.casefold().encode()).hexdigest(),
        "purpose": "mobile-page-v1",
        "project": str(DEFAULT_PROJECT_ID),
    }
    order = ()
    if cursor:
        page = _read_cursor(cursor, key)
        order = (
            or_(
                User.username > page["last_name"],
                and_(User.username == page["last_name"], User.id > UUID(page["last_id"])),
            ),
        )
    subjects = await _synthetic_subjects(db, viewer)
    rows = await db.scalars(
        select(User)
        .where(
            User.auth_provider != "deactivated",
            or_(User.username.ilike(pattern, escape="\\"), User.name.ilike(pattern, escape="\\")),
            *((User.id.in_(subjects),) if subjects is not None else ()),
            *order,
        )
        .order_by(User.username, User.id)
        .limit(limit + 1)
    )
    found = rows.all()
    page_items = found[:limit]
    next_cursor = (
        _cursor({**key, "last_name": page_items[-1].username, "last_id": str(page_items[-1].id)})
        if len(found) > limit
        else None
    )
    return PeoplePage(
        items=[PublicPerson.model_validate(row, from_attributes=True) for row in page_items],
        complete=next_cursor is None,
        next_cursor=next_cursor,
    )


@router.post("/people/resolve", response_model=PeoplePage)
async def resolve_people(
    request: ResolveRequest, db: AsyncSession = Depends(get_db), viewer: User = Depends(get_mobile_user)
):
    subjects = await _synthetic_subjects(db, viewer)
    if len(set(request.subject_ids)) != len(request.subject_ids):
        raise HTTPException(422, "Distinct subjects required")
    rows = await db.scalars(
        select(User).where(
            User.id.in_(request.subject_ids),
            User.auth_provider != "deactivated",
            *((User.id.in_(subjects),) if subjects is not None else ()),
        )
    )
    indexed = {row.id: row for row in rows.all()}
    return PeoplePage(
        items=[
            PublicPerson.model_validate(indexed[ident], from_attributes=True)
            for ident in request.subject_ids
            if ident in indexed
        ],
        complete=True,
    )


def _page_binding(viewer: User, subject: UUID, scope: Scope, anchor: str, revision: str) -> dict:
    # All inputs remain bound, but a short digest leaves room for the keyset
    # tuple inside the signed 512-character cursor query limit.
    digest = hashlib.sha256(
        json.dumps(
            [str(viewer.id), str(subject), scope, str(DEFAULT_PROJECT_ID), anchor, revision],
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    return {"binding": digest, "purpose": "mobile-page-v1", "project": str(DEFAULT_PROJECT_ID)}


@router.get("/people/{subject_id}/{scope}/components", response_model=ComponentPage)
async def components(
    subject_id: UUID,
    scope: Scope,
    period: Period,
    window_anchor: str = Query(max_length=512),
    expected_revision: str = Query(max_length=512),
    cursor: str | None = Query(None, max_length=512),
    db: AsyncSession = Depends(get_db),
    viewer: User = Depends(get_mobile_user),
):
    if not await _authorize(viewer, subject_id, scope, db):
        return Response(status_code=403)
    window, anchor = _paired_window(viewer, period, window_anchor)
    if not await readable(db, str(DEFAULT_PROJECT_ID)):
        return ComponentPage(
            subject_id=subject_id, scope=scope, window=window, window_anchor=anchor, revision="unqualified"
        )
    revision = await _scope_revision(db, viewer, subject_id, scope, anchor)
    if revision != expected_revision:
        raise HTTPException(409, "stale_cursor")
    binding = _page_binding(viewer, subject_id, scope, anchor, revision)
    after = None
    if cursor:
        claims = _read_cursor(cursor, binding)
        try:
            kind = claims["last_kind"]
            if kind not in ("mcp", "skill", "hook"):
                raise ValueError("invalid component kind")
            after = (int(claims["last_roots"]), kind, UUID(claims["last_id"]))
        except (ValueError, TypeError, KeyError) as exc:
            raise HTTPException(409, "stale_cursor") from exc
    found = await trace_component_page(
        db,
        subject_id,
        scope,
        str(DEFAULT_PROJECT_ID),
        window.start,
        window.end,
        viewer_self=viewer.id == subject_id,
        actor_ids=await _synthetic_subjects(db, viewer),
        after=after,
    )
    if await _scope_revision(db, viewer, subject_id, scope, anchor) != revision:
        raise HTTPException(409, "stale_cursor")
    if found is None:
        return ComponentPage(subject_id=subject_id, scope=scope, window=window, window_anchor=anchor, revision=revision)
    items = [_component(row) for row in found[:20]]
    more = len(found) > 20
    next_cursor = (
        _cursor(
            {
                **binding,
                "last_roots": found[19]["roots"],
                "last_kind": found[19].get("kind", "mcp"),
                "last_id": str(found[19]["id"]),
            }
        )
        if more
        else None
    )
    return ComponentPage(
        subject_id=subject_id,
        scope=scope,
        window=window,
        window_anchor=anchor,
        revision=revision,
        items=items,
        complete=not more,
        next_cursor=next_cursor,
    )


@router.get("/people/{subject_id}/{scope}/components/{kind}/{component_id}", response_model=ComponentDetail)
async def component_detail(
    subject_id: UUID,
    scope: Scope,
    kind: Literal["mcp", "skill", "hook"],
    component_id: UUID,
    period: Period,
    window_anchor: str = Query(max_length=512),
    expected_revision: str = Query(max_length=512),
    db: AsyncSession = Depends(get_db),
    viewer: User = Depends(get_mobile_user),
):
    if not await _authorize(viewer, subject_id, scope, db):
        return Response(status_code=403)
    if not await readable(db, str(DEFAULT_PROJECT_ID)):
        raise HTTPException(404, "Not found")
    window, anchor = _paired_window(viewer, period, window_anchor)
    revision = await _scope_revision(db, viewer, subject_id, scope, anchor)
    if revision != expected_revision:
        raise HTTPException(409, "stale_cursor")
    found = await trace_component_page(
        db,
        subject_id,
        scope,
        str(DEFAULT_PROJECT_ID),
        window.start,
        window.end,
        viewer_self=viewer.id == subject_id,
        actor_ids=await _synthetic_subjects(db, viewer),
        component=component_id,
        kind=kind,
        limit=1,
    )
    if await _scope_revision(db, viewer, subject_id, scope, anchor) != revision:
        raise HTTPException(409, "stale_cursor")
    if not found or found[0].get("kind", "mcp") != kind:
        raise HTTPException(404, "Not found")
    return ComponentDetail(
        subject_id=subject_id,
        scope=scope,
        window=window,
        window_anchor=anchor,
        revision=revision,
        component=_component(found[0]),
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
    cursor: str | None = Query(None, max_length=512),
    db: AsyncSession = Depends(get_db),
    viewer: User = Depends(get_mobile_user),
):
    binding = {
        "purpose": "mobile-page-v1",
        "project": str(DEFAULT_PROJECT_ID),
        "sub": str(viewer.id),
        "collection": "published",
    }
    params = {"viewer": viewer.id, "limit": limit + 1}
    after_sql = ""
    if cursor:
        page = _read_cursor(cursor, binding)
        try:
            last_kind, last_id = page["last_kind"], UUID(page["last_id"])
        except (ValueError, TypeError, KeyError) as exc:
            raise HTTPException(409, "stale_cursor") from exc
        if last_kind not in {item[0] for item in _PUBLISHED}:
            raise HTTPException(409, "stale_cursor")
        after_sql = " WHERE (kind,id)>(:last_kind,CAST(:last_id AS uuid))"
        params.update(last_kind=last_kind, last_id=last_id)
    branches = []
    for kind, listing, version, version_fk in _PUBLISHED:
        current_owner = "created_by" if kind == "agent" else "submitted_by"
        deleted = "AND l.deleted_at IS NULL" if kind == "agent" else ""
        branches.append(
            f"SELECT '{kind}' AS kind, l.id, l.name, "
            f"(l.{current_owner} = :viewer) AS is_current_owner "
            f"FROM mobile_listing_provenance p JOIN {listing} l ON l.id = p.listing_id "
            f"WHERE p.kind = '{kind}' AND p.original_author_id = :viewer "
            f"AND l.is_private = false {deleted} "
            f"AND EXISTS (SELECT 1 FROM {version} v "
            f"WHERE v.{version_fk} = l.id AND v.status = 'approved' "
            f"AND (SELECT e.status FROM mobile_publication_events e "
            f"WHERE e.kind = '{kind}' AND e.listing_id=l.id AND e.version_id=v.id "
            f"ORDER BY e.recorded_at DESC,e.id DESC LIMIT 1)='approved')"
        )
    # Author-scoped provenance, current approval, and a bound tuple cursor.
    # Missing/deleted/private rows cannot be recovered from a stale cursor.
    sql = (
        "SELECT * FROM (" + " UNION ALL ".join(branches) + ") published" + after_sql + " ORDER BY kind,id LIMIT :limit"
    )
    rows = (await db.execute(text(sql), params)).mappings().all()
    visible = rows[:limit]
    more = len(rows) > limit
    next_cursor = (
        _cursor({**binding, "last_kind": visible[-1]["kind"], "last_id": str(visible[-1]["id"])}) if more else None
    )
    return PublishedPage(
        items=[PublishedItem.model_validate(row) for row in visible], complete=not more, next_cursor=next_cursor
    )
