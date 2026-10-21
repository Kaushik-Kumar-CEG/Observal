# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Adversarial follow authority and one-use browser approval (no external services)."""

import importlib
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import jwt
import pytest
from fastapi import HTTPException
from redis.exceptions import ConnectionError
from starlette.requests import Request

from services.jwt_service import MOBILE_AUDIENCE, MOBILE_CLIENT_ID, MOBILE_SCOPE

F = importlib.import_module("services.mobile_follow_auth")
OWNER = uuid.uuid4()
SERVER = uuid.uuid4()
DEVICE = "opaque-device-id"
SECRET = "isolated-tests-only-32-byte-test-key"


def request(method, suffix):
    return Request(
        {
            "type": "http",
            "method": method,
            "path": F.ROOT + suffix,
            "headers": [],
            "query_string": b"",
            "scheme": "https",
            "server": ("example.test", 443),
        }
    )


def signed(payload):
    return jwt.encode(payload, SECRET, algorithm="HS256")


def verified(token):
    return jwt.decode(token, SECRET, algorithms=["HS256"], options={"verify_aud": False})


def claims(kind="follow-write", **updates):
    now = int(datetime.now(UTC).timestamp())
    value = dict(
        sub=str(OWNER),
        jti=str(uuid.uuid4()),
        type=kind,
        iat=now,
        iat_us=now * 1_000_000,
        exp=now + 300,
        client_id=MOBILE_CLIENT_ID,
        aud=F.AUDIENCE,
        scope=F.SCOPE,
        device_id=DEVICE,
        server_id=str(SERVER),
        project_id=F.PROJECT,
        cohort="live",
        owner_generation=7,
    )
    value.update(updates)
    return value


class Redis:
    def __init__(self):
        self.values = {}
        self.error = False

    async def get(self, key):
        if self.error:
            raise ConnectionError("redis unavailable")
        return self.values.get(key)


class DB:
    def __init__(self):
        self.user = SimpleNamespace(id=OWNER, auth_provider="local", role="user")
        self.partition = SimpleNamespace(owner_generation=7, consent_state="available", removal_state="none")
        self.approval = None
        self.deleted = []
        self.added = []

    async def scalar(self, stmt):
        sql = str(stmt)
        if "mobile_server_identity" in sql:
            return SERVER
        if "FROM users" in sql:
            return self.user if self.user.id in stmt.compile().params.values() else None
        if "FROM mobile_follow_partitions" in sql:
            return self.partition
        if "FROM mobile_follow_approvals" in sql:
            return self.approval
        raise AssertionError(sql)

    def add(self, row):
        self.approval = row
        self.added.append(row)

    async def delete(self, row):
        self.deleted.append(row)
        if row is self.approval:
            self.approval = None

    async def flush(self):
        pass


@pytest.fixture
def env(monkeypatch):
    db, redis = DB(), Redis()
    monkeypatch.setattr(F, "get_redis", lambda: redis)
    monkeypatch.setattr(F, "verify_token", verified)
    monkeypatch.setattr(F, "sign_token", signed)
    original_decode = F.decode_access_token
    monkeypatch.setattr("services.crypto.verify_token", verified)
    monkeypatch.setattr(F, "decode_access_token", original_decode)

    async def active(db, user, *, server_id):
        assert server_id == str(SERVER)
        return "live"

    monkeypatch.setattr(F, "active_mobile_cohort", active)
    return db, redis


def read_claims(**updates):
    value = claims("access", aud=MOBILE_AUDIENCE, scope=MOBILE_SCOPE)
    value.update(updates)
    return signed(value)


async def write(db, token, suffix="operations", method="POST"):
    return await F.authorize_follow_write(request(method, suffix), "Bearer " + token, db)


@pytest.mark.asyncio
async def test_separate_scope_and_exact_route_allowlist(env):
    db, _ = env
    token = signed(claims())
    p = await write(db, token)
    assert p.generation == 7 and p.device_id == DEVICE
    for method, route in [
        ("GET", "availability"),
        ("POST", "write-grant"),
        ("POST", "../operations"),
        ("POST", "operations/extra"),
    ]:
        with pytest.raises(HTTPException) as error:
            await write(db, token, route, method)
        assert error.value.status_code == 403
    with pytest.raises(HTTPException) as error:
        await F.authorize_follow_read(request("POST", "operations"), "Bearer " + read_claims(), db)
    assert error.value.status_code == 403
    with pytest.raises(HTTPException):
        await F.authorize_follow_write(request("POST", "operations"), "Bearer " + read_claims(), db)
    for suffix in ("operations", "removals", "consent/withdrawals"):
        await F.authorize_follow_read(request("GET", suffix + "/" + str(uuid.uuid4())), "Bearer " + read_claims(), db)
    with pytest.raises(HTTPException):
        await F.authorize_follow_read(request("GET", "operations/not-a-uuid"), "Bearer " + read_claims(), db)
    with pytest.raises(HTTPException):
        await F.authorize_browser_approval(request("POST", "write-approval"), "Bearer " + read_claims(), db)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "changed",
    [
        {"scope": MOBILE_SCOPE},
        {"aud": MOBILE_AUDIENCE},
        {"type": "access"},
        {"owner_generation": 7.0},
        {"owner_generation": True},
        {"owner_generation": 8},
        {"device_id": ""},
        {"project_id": "other"},
        {"cohort": "synthetic-user"},
        {"server_id": str(uuid.uuid4())},
        {"exp": int(datetime.now(UTC).timestamp()) + 301},
    ],
)
async def test_claims_fail_closed(env, changed):
    db, _ = env
    value = claims(**changed)
    if "exp" in changed:
        value["exp"] = value["iat"] + 301
    with pytest.raises(HTTPException) as error:
        await write(db, signed(value))
    assert error.value.status_code == 401


@pytest.mark.asyncio
async def test_account_device_jti_redis_and_policy_revoke(env, monkeypatch):
    db, redis = env
    payload = claims()
    token = signed(payload)
    for key in (f"revoked_jti:{payload['jti']}", f"revoked_mobile_device:{DEVICE}", f"revoked_user:{OWNER}"):
        redis.values[key] = "1"
        with pytest.raises(HTTPException) as error:
            await write(db, token)
        assert error.value.status_code == 401
        redis.values.clear()
    redis.error = True
    with pytest.raises(HTTPException) as error:
        await write(db, token)
    assert error.value.status_code == 503
    redis.error = False
    db.user.auth_provider = "deactivated"
    with pytest.raises(HTTPException):
        await write(db, token)
    db.user.auth_provider = "local"
    db.partition.owner_generation = 8
    with pytest.raises(HTTPException) as error:
        await write(db, token)
    assert error.value.status_code == 401
    db.partition.owner_generation = 7
    db.partition.consent_state = "withdrawal_pending"
    await F.authorize_follow_read(request("GET", "operations/" + str(uuid.uuid4())), "Bearer " + read_claims(), db)
    with pytest.raises(HTTPException):
        await write(db, token)
    db.partition.consent_state = "available"
    db.partition.removal_state = "pending"
    with pytest.raises(HTTPException):
        await write(db, token)
    db.partition.removal_state = "none"
    monkeypatch.setattr(F, "active_mobile_cohort", lambda *args, **kwargs: no_cohort())
    with pytest.raises(HTTPException) as error:
        await write(db, token)
    assert error.value.status_code == 403


async def no_cohort():
    return None


@pytest.mark.asyncio
async def test_fresh_read_state_requires_barrier_and_owner_lock(env, monkeypatch):
    db, _ = env
    db.partition = None
    events = []
    original_scalar = db.scalar

    async def scalar(stmt):
        sql = str(stmt)
        if "FROM users" in sql and "FOR UPDATE" in sql:
            events.append("owner_lock")
            return OWNER
        return await original_scalar(stmt)

    async def execute(stmt, params):
        assert "ON CONFLICT DO NOTHING" in str(stmt)
        assert events == ["cohort", "owner_lock"]
        assert params["owner"] == OWNER and params["cohort"] == "live"
        events.append("insert")
        db.partition = SimpleNamespace(owner_generation=1, consent_state="consent_required", removal_state="none")

    async def active(*args, **kwargs):
        events.append("cohort")
        return "live"

    db.scalar = scalar
    db.execute = execute
    monkeypatch.setattr(F, "active_mobile_cohort", active)
    # A normal read must not create missing consent or widen write authority.
    with pytest.raises(HTTPException) as denied:
        await F.authorize_follow_read(request("GET", "snapshot"), "Bearer " + read_claims(), db)
    assert denied.value.status_code == 403 and events == ["cohort"]
    events.clear()
    await F._cohort(db, db.user, SERVER)
    row = await F._partition(db, db.user, SERVER, "live", exclusive=True, create=True)
    assert row.consent_state == "consent_required" and events == ["cohort", "owner_lock", "insert"]
    events.clear()
    db.partition = None

    async def closed(*args, **kwargs):
        return None

    monkeypatch.setattr(F, "active_mobile_cohort", closed)
    with pytest.raises(HTTPException):
        await F.authorize_follow_read(request("GET", "availability"), "Bearer " + read_claims(), db)
    assert events == []


@pytest.mark.asyncio
async def test_browser_same_owner_challenge_approval_and_one_use_grant(env):
    db, _ = env
    read = await F.authorize_follow_read(request("POST", "write-authorization"), "Bearer " + read_claims(), db)
    code = await F.create_challenge(db, read)
    assert 20 <= len(code) <= 64
    browser_token = signed(
        {
            k: v
            for k, v in claims("access").items()
            if k
            not in ("aud", "scope", "device_id", "client_id", "owner_generation", "server_id", "project_id", "cohort")
        }
    )
    browser = await F.authorize_browser_approval(request("POST", "write-approval"), "Bearer " + browser_token, db)
    old_claims = verified(browser_token)
    old_claims["iat"] -= 301
    old_claims["iat_us"] -= 301_000_000
    with pytest.raises(HTTPException) as old_error:
        await F.authorize_browser_approval(request("POST", "write-approval"), "Bearer " + signed(old_claims), db)
    assert old_error.value.status_code == 403
    admin_other = signed({**verified(browser_token), "sub": str(uuid.uuid4()), "role": "super_admin"})
    with pytest.raises(HTTPException):
        await F.authorize_browser_approval(request("POST", "write-approval"), "Bearer " + admin_other, db)
    with pytest.raises(HTTPException):
        await F.approve_challenge(db, browser, "wrong-but-long-enough-code")
    await F.approve_challenge(db, browser, code)
    with pytest.raises(HTTPException):
        await F.approve_challenge(db, browser, code)
    grant, lifetime = await F.create_write_grant(db, read)
    assert lifetime == 300
    assert verified(grant)["scope"] == F.SCOPE
    assert verified(grant)["exp"] - verified(grant)["iat"] == 300
    await write(db, grant)
    with pytest.raises(HTTPException):
        await F.create_write_grant(db, read)
    assert db.approval is None


@pytest.mark.asyncio
async def test_cross_account_generation_expiry_and_unapproved_cannot_grant(env):
    db, _ = env
    principal = await F.authorize_follow_read(request("POST", "write-authorization"), "Bearer " + read_claims(), db)
    code = await F.create_challenge(db, principal)
    with pytest.raises(HTTPException):
        await F.create_write_grant(db, principal)
    other = SimpleNamespace(**{**vars(principal), "user": SimpleNamespace(id=uuid.uuid4())})
    # Real DB lookup scopes approvals to the complete owner key; emulate that lookup.
    original = db.scalar

    async def owner_scoped(stmt):
        if "FROM mobile_follow_approvals" in str(stmt):
            assert other.user.id in stmt.compile().params.values()
            return None
        return await original(stmt)

    db.scalar = owner_scoped
    with pytest.raises(HTTPException):
        await F.approve_challenge(db, other, code)
    db.scalar = original
    db.partition.owner_generation = 8
    with pytest.raises(HTTPException) as error:
        await F.approve_challenge(db, principal, code)
    assert error.value.status_code == 409
    with pytest.raises(HTTPException):
        await F.create_write_grant(db, principal)
    db.partition.owner_generation = 7
    db.approval.expires_at = datetime.now(UTC) - timedelta(seconds=1)
    with pytest.raises(HTTPException):
        await F.approve_challenge(db, principal, code)
