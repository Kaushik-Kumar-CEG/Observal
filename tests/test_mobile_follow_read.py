# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Contract fixtures for the dormant 1.0.5 read router."""

import asyncio
import json
import sys
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import jsonschema
import pytest
import yaml
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012
from starlette.requests import Request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "observal-server"))
sys.path.insert(0, str(ROOT / "packages/observal-shared"))
from api.routes import mobile_follow_read as read  # noqa: E402
from services import mobile_follow_cursor as cursor  # noqa: E402
from services.mobile_follow_store import StoreFenceError  # noqa: E402

SPEC = yaml.safe_load((ROOT / "contracts/mobile-activity-v1/follow-sync-v105-openapi.yaml").read_text())
URI = "https://observal.example.test/mobile-follow-sync/1.0.5"
REGISTRY = Registry().with_resource(URI, Resource.from_contents(SPEC, default_specification=DRAFT202012))
OWNER = uuid.uuid4()
SERVER = uuid.uuid4()
LEASE = uuid.uuid4()
SUBJECT = uuid.uuid4()


def validate(name, value):
    jsonschema.Draft202012Validator(
        {"$ref": f"{URI}#/components/schemas/{name}"}, registry=REGISTRY, format_checker=jsonschema.FormatChecker()
    ).validate(value)


def request(path, query=""):
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": f"/api/v1/mobile-follow-sync/v1/{path}",
            "query_string": query.encode(),
            "headers": [],
        }
    )


@pytest.fixture
def setup(monkeypatch):
    p = SimpleNamespace(
        server_id=SERVER,
        project_id="default",
        user=SimpleNamespace(id=OWNER),
        cohort="live",
        device_id="phone",
        generation=1,
    )
    row = SimpleNamespace(owner_generation=1, consent_state="available", removal_state="none", current_revision=100)

    async def principal(*args, **kwargs):
        return p, row

    monkeypatch.setattr(read, "principal_for", principal)
    return p, row


@pytest.mark.asyncio
async def test_read_route_auth_errors_follow_strict_schema(monkeypatch):
    import httpx
    from fastapi import FastAPI, HTTPException

    from api.deps import get_db

    app = FastAPI()
    app.include_router(read.router)

    async def fake_db():
        yield object()

    app.dependency_overrides[get_db] = fake_db

    async def denied(*args, **kwargs):
        raise HTTPException(401, "secret token detail")

    monkeypatch.setattr(read, "principal_for", denied)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        for path in ("availability", "consent/state", f"operations/{LEASE}"):
            response = await client.get(f"/api/v1/mobile-follow-sync/v1/{path}")
            assert response.status_code == 401
            assert response.json() == {"error": "unauthorized"}
            validate("Error", response.json())

        async def unavailable(*args, **kwargs):
            raise HTTPException(503, "internal")

        monkeypatch.setattr(read, "principal_for", unavailable)
        response = await client.get("/api/v1/mobile-follow-sync/v1/availability")
        assert response.status_code == 503 and response.headers["retry-after"] == "1"
        validate("Error", response.json())


def test_canonical_numbers():
    assert read.number("0") == 0
    assert read.number(str(read.SAFE)) == read.SAFE
    for raw in ("", "01", "+1", "-1", "1.0", " 1", "9007199254740992", "\u0661", "1e2"):
        with pytest.raises(ValueError):
            read.number(raw)
    with pytest.raises(ValueError):
        read.number("0", positive=True)


def test_cursor_bindings_and_boundary(monkeypatch):
    now = datetime.now(UTC).replace(microsecond=0)
    # The signing service is mocked, not the identity/purpose validation logic.
    # Use a wire-safe fake serializer for this unit; real JWT signing is tested elsewhere.
    import base64

    monkeypatch.setattr(
        cursor,
        "sign_token",
        lambda payload: "e30." + base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=") + ".sig",
    )
    monkeypatch.setattr(
        cursor,
        "verify_token",
        lambda token: json.loads(base64.urlsafe_b64decode(token.split(".")[1] + "=" * (-len(token.split(".")[1]) % 4))),
    )
    kwargs = dict(
        purpose="changes",
        server_id=SERVER,
        project_id="default",
        owner_id=OWNER,
        device_id="phone",
        cohort="live",
        generation=1,
    )
    token = cursor.issue(**kwargs, lease_id=LEASE, last_row=100, expires_at=now + timedelta(seconds=900))
    assert cursor.verify(token, **kwargs, now=now + timedelta(seconds=899)) == (LEASE, 100)
    with pytest.raises(cursor.InvalidCursor):
        cursor.verify(token, **kwargs, now=now + timedelta(seconds=900))
    for changed in (
        dict(purpose="snapshot"),
        dict(owner_id=uuid.uuid4()),
        dict(device_id="other"),
        dict(cohort="synthetic"),
        dict(server_id=uuid.uuid4()),
    ):
        with pytest.raises(cursor.InvalidCursor):
            cursor.verify(token, **(kwargs | changed), now=now)
    with pytest.raises(cursor.GenerationConflict):
        cursor.verify(token, **(kwargs | {"generation": 2}), now=now)


def test_exact_fractional_lease(monkeypatch):
    import base64

    monkeypatch.setattr(
        cursor,
        "sign_token",
        lambda payload: "e30." + base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=") + ".sig",
    )
    monkeypatch.setattr(
        cursor,
        "verify_token",
        lambda token: json.loads(base64.urlsafe_b64decode(token.split(".")[1] + "=" * (-len(token.split(".")[1]) % 4))),
    )
    start = datetime(2026, 1, 1, tzinfo=UTC)
    deadline = start + timedelta(seconds=900, microseconds=350000)
    bindings = dict(
        purpose="snapshot",
        server_id=SERVER,
        project_id="default",
        owner_id=OWNER,
        device_id="phone",
        cohort="live",
        generation=1,
    )
    signed = cursor.issue(**bindings, lease_id=LEASE, last_row=100, expires_at=deadline)
    assert cursor.verify(signed, **bindings, now=start + timedelta(seconds=899, microseconds=350000)) == (LEASE, 100)
    with pytest.raises(cursor.InvalidCursor):
        cursor.verify(signed, **bindings, now=deadline)
    with pytest.raises(cursor.GenerationConflict):
        cursor.verify(signed, **(bindings | {"generation": 2}), now=start)
    with pytest.raises(cursor.InvalidCursor) as exc:
        cursor.verify(signed + "!", **(bindings | {"generation": 2}), now=start)
    assert not isinstance(exc.value, cursor.GenerationConflict)


def test_signed_cursor_rejects_tamper_and_preserves_fractional_expiry(monkeypatch):
    import jwt

    secret = "test-only-signing-key-32-bytes-long"
    monkeypatch.setattr(cursor, "sign_token", lambda payload: jwt.encode(payload, secret, algorithm="HS256"))
    monkeypatch.setattr(
        cursor,
        "verify_token",
        lambda token: jwt.decode(token, secret, algorithms=["HS256"], options={"verify_aud": False}),
    )
    start = datetime.now(UTC)
    deadline = start + timedelta(seconds=900)
    bindings = dict(
        purpose="snapshot",
        server_id=SERVER,
        project_id="default",
        owner_id=OWNER,
        device_id="phone",
        cohort="live",
        generation=1,
    )
    signed = cursor.issue(**bindings, lease_id=LEASE, last_row=100, expires_at=deadline)
    assert cursor.verify(signed, **bindings, now=deadline - timedelta(microseconds=1)) == (LEASE, 100)
    with pytest.raises(cursor.InvalidCursor):
        cursor.verify(signed, **bindings, now=deadline)
    with pytest.raises(cursor.GenerationConflict):
        cursor.verify(signed, **(bindings | {"generation": 2}), now=start)
    header, body, signature = signed.split(".")
    tampered = ".".join((header, body, ("B" if signature[0] == "A" else "A") + signature[1:]))
    with pytest.raises(cursor.InvalidCursor) as exc:
        cursor.verify(tampered, **(bindings | {"generation": 2}), now=start)
    assert not isinstance(exc.value, cursor.GenerationConflict)


@pytest.mark.asyncio
async def test_fresh_state_routes_initialize_only_their_own_partition(monkeypatch):
    calls = []
    user = SimpleNamespace(id=OWNER)

    monkeypatch.setattr(
        read,
        "decode_access_token",
        lambda token, **kwargs: (
            {
                "client_id": read.MOBILE_CLIENT_ID,
                "aud": read.MOBILE_AUDIENCE,
                "scope": read.MOBILE_SCOPE,
                "device_id": "phone",
            }
            if kwargs.get("allow_mobile")
            else {}
        ),
    )
    monkeypatch.setattr(read.auth, "_account", lambda *args, **kwargs: async_value(user))
    monkeypatch.setattr(read.auth, "_identity", lambda *args: async_value(SERVER))
    monkeypatch.setattr(read.auth, "_cohort", lambda *args: async_value("live"))

    async def partition(db, user, server, cohort, **kwargs):
        calls.append(kwargs)
        return SimpleNamespace(owner_generation=1, consent_state="consent_required", removal_state="none")

    monkeypatch.setattr(read.auth, "_partition", partition)
    for path in ("availability", "consent/state", "snapshot"):
        await read.principal_for(request(path), "Bearer test", object(), browser=path == "consent/state")
    assert calls == [
        {"exclusive": True, "create": True},
        {"exclusive": True, "create": True},
        {"exclusive": True, "create": False},
    ]


async def async_value(value):
    return value


def test_availability_and_browser_state(setup):
    class DB:
        async def commit(self):
            pass

    db = DB()
    payload = asyncio.run(read.availability(request("availability"), "bearer", db))
    validate("Availability", payload)
    payload = asyncio.run(read.consent_state(request("consent/state"), "bearer", db))
    validate("BrowserConsentState", payload)


def test_pages_contract_throttle_and_reuse(monkeypatch, setup):
    p, row = setup
    calls = []
    commits = []

    class DB:
        async def scalar(self, statement, params):
            return 0

        async def commit(self):
            commits.append(True)

    db = DB()

    async def admit(*args, **kwargs):
        calls.append("admit")
        return LEASE

    async def expiry(*args):
        return datetime.now(UTC) + timedelta(minutes=15)

    async def page(*args, **kwargs):
        calls.append(("page", kwargs["last_row"], kwargs["throttle"]))
        if len([c for c in calls if isinstance(c, tuple)]) == 1:
            raise StoreFenceError("rate_limited")
        return dict(
            owner_generation=1,
            revision=100,
            erasure_floor=0,
            complete=True,
            items=[dict(subject_id=SUBJECT, person_revision=1, following=True, revision=100, ordinal=0)],
            last_row=1,
        )

    monkeypatch.setattr(read, "admit_lease", admit)
    monkeypatch.setattr(read, "lease_page", page)
    monkeypatch.setattr(read, "_lease_expiry", expiry)
    # The purpose binding remains exercised; signing internals are independently tested above.
    monkeypatch.setattr(read.cursor, "issue", lambda **kwargs: "retry.safe")
    monkeypatch.setattr(read.cursor, "verify", lambda token, **kwargs: (LEASE, 0))
    for purpose in ("snapshot", "export", "changes"):
        calls.clear()
        query = "after_revision=0&owner_generation=1" if purpose == "changes" else ""
        first = asyncio.run(read._page(request(purpose, query), "bearer", db, purpose))
        validate("PageRetry", json.loads(first.body))
        assert first.status_code == 429 and commits
        second_query = query + ("&" if query else "") + "cursor=retry.safe"
        second = asyncio.run(read._page(request(purpose, second_query), "bearer", db, purpose))
        validate("ChangesPage" if purpose == "changes" else "SnapshotPage", second)
        assert calls.count("admit") == 1


def test_rejects_unsafe_page_arguments(setup):
    for query in ("limit=1", "limit=0100", "min_revision=9007199254740992", "cursor=bad"):
        result = asyncio.run(read._page(request("snapshot", query), "bearer", None, "snapshot"))
        assert result.status_code == 400
        validate("Error", json.loads(result.body))


def test_min_revision_not_yet_visible(setup):
    result = asyncio.run(read._page(request("snapshot", "min_revision=101"), "bearer", None, "snapshot"))
    assert result.status_code == 503 and result.headers["retry-after"] == "1"
    validate("Error", json.loads(result.body))


def test_incomplete_page_exactly_one_hundred(monkeypatch, setup):
    class DB:
        async def commit(self):
            pass

    async def admit(*args, **kwargs):
        return LEASE

    async def page(*args, **kwargs):
        return dict(
            owner_generation=1,
            revision=100,
            erasure_floor=0,
            complete=False,
            last_row=100,
            items=[dict(subject_id=SUBJECT, person_revision=1)] * 100,
        )

    async def expiry(*args):
        return datetime.now(UTC) + timedelta(minutes=15)

    monkeypatch.setattr(read, "admit_lease", admit)
    monkeypatch.setattr(read, "lease_page", page)
    monkeypatch.setattr(read, "_lease_expiry", expiry)
    monkeypatch.setattr(read.cursor, "issue", lambda **kwargs: "signed.page")
    result = asyncio.run(read._page(request("snapshot"), "bearer", DB(), "snapshot"))
    validate("SnapshotPage", result)
    assert len(result["items"]) == 100 and result["next_cursor"] == "signed.page"


def test_uncommitted_minimum_revision_is_unavailable(setup):
    result = asyncio.run(read._page(request("snapshot", "min_revision=101"), "bearer", None, "snapshot"))
    assert result.status_code == 503 and result.headers["retry-after"] == "1"
    validate("Error", json.loads(result.body))


def test_older_shared_image_does_not_block_new_minimum_with_free_slot(monkeypatch, setup):
    _principal, row = setup
    row.current_revision = 101
    seen = []

    async def admit(*args, **kwargs):
        seen.append(kwargs["min_revision"])
        return LEASE

    async def page(*args, **kwargs):
        return dict(owner_generation=1, revision=101, erasure_floor=0, complete=True, last_row=0, items=[])

    monkeypatch.setattr(read, "admit_lease", admit)
    monkeypatch.setattr(read, "lease_page", page)
    result = asyncio.run(
        read._page(request("snapshot", "min_revision=101"), "bearer", SimpleNamespace(commit=AsyncMock()), "snapshot")
    )
    assert seen == [101]
    assert result["revision"] == 101 and result["complete"] is True
    validate("SnapshotPage", result)


def test_stale_signed_cursor_route_is_conflict(monkeypatch, setup):
    p, row = setup
    row.owner_generation = 2
    row.consent_state = "consent_required"

    def stale(*args, **kwargs):
        raise cursor.GenerationConflict

    monkeypatch.setattr(read.cursor, "verify", stale)
    result = asyncio.run(read._page(request("snapshot", "cursor=signed.old"), "bearer", None, "snapshot"))
    assert result.status_code == 409
    assert json.loads(result.body) == {"error": "generation_conflict"}
    validate("Error", json.loads(result.body))


def test_withdrawal_blocks_page_but_historical_lookup(monkeypatch, setup):
    p, row = setup
    row.consent_state = "withdrawal_pending"
    result = asyncio.run(read._page(request("snapshot"), "bearer", None, "snapshot"))
    assert result.status_code == 403

    async def status(*args):
        return dict(
            operation_id=str(LEASE),
            owner_generation=2,
            original_http_status=200,
            effective=False,
            result=dict(status="superseded", reason="owner_reset", original_owner_generation=1, owner_generation=2),
        )

    monkeypatch.setattr(read, "operation_status", status)

    class DB:
        async def commit(self):
            pass

    outcome = asyncio.run(read.operation(request(f"operations/{LEASE}"), str(LEASE), "bearer", DB()))
    validate("OperationOutcome", outcome)
    assert outcome["effective"] is False and "subject_id" not in str(outcome)
