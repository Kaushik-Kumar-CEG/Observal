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

from models.user import UserRole
from services.jwt_service import MOBILE_AUDIENCE, MOBILE_CLIENT_ID, MOBILE_SCOPE, create_access_token
from services.token_revocation import is_revoked, revoke_user_tokens

F = importlib.import_module("services.mobile_follow_auth")
OWNER = uuid.uuid4()
SERVER = uuid.uuid4()
DEVICE = "opaque-device-id"
SECRET = "isolated-tests-only-32-byte-test-key"


def request(method, suffix):
    request = Request(
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
    request.state.normal_follow_router = True
    return request


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
        browser_action_epoch=1,
        iat=now,
        iat_us=now * 1_000_000,
        parent_issued_us=now * 1_000_000,
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
    value["parent_jti"] = str(uuid.uuid4())
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

    async def eval(self, _script, _numkeys, key, value):
        if self.error:
            raise ConnectionError("redis unavailable")
        self.values[key] = str(max(int(self.values.get(key, 0)), int(value)))


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
    del value["parent_jti"]
    value.update(updates)
    return signed(value)


async def write(db, token, suffix="operations", method="POST"):
    return await F.authorize_follow_write(request(method, suffix), "Bearer " + token, db)


@pytest.mark.asyncio
async def test_logout_after_grant_check_cannot_resurrect_phone_authority(env, monkeypatch):
    from services import mobile_follow_browser

    db, redis = env
    now = int(datetime.now(UTC).timestamp())
    phone = read_claims(iat=now - 60, iat_us=(now - 60) * 1_000_000, exp=now + 600)
    principal = await F.authorize_follow_read(request("POST", "write-grant"), "Bearer " + phone, db)
    db.approval = SimpleNamespace(
        device_id=DEVICE,
        status="approved",
        owner_generation=7,
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
        approved_at=datetime.now(UTC),
    )
    db.approval.browser_action_proven = True

    commits = 0

    async def commit():
        nonlocal commits
        commits += 1
        if commits == 2:
            # Another API process handles logout after the grant's last account check.
            await revoke_user_tokens(redis, OWNER)

    db.commit = commit

    async def operator_enabled(session):
        assert session is db and commits == 1

    monkeypatch.setattr("services.mobile_follow_enablement.require_operator_approval", operator_enabled)
    monkeypatch.setattr("services.crypto.sign_token", signed)
    grant, ttl = await mobile_follow_browser.consume_grant_before_mint(db, principal, action_proven=True)
    assert commits == 2 and ttl == 300 and db.approval.status == "approved"
    marker = redis.values.pop(f"revoked_user:{OWNER}")
    await write(db, grant)  # Ensure no unrelated guard masks the race.
    redis.values[f"revoked_user:{OWNER}"] = marker
    assert not is_revoked(marker, verified(grant)["iat_us"])
    assert is_revoked(marker, verified(grant)["parent_issued_us"])
    with pytest.raises(HTTPException) as denied:
        await write(db, grant)
    assert denied.value.status_code == 401


@pytest.mark.asyncio
@pytest.mark.parametrize("epoch", (None, True, 0, 2, "1"))
async def test_legacy_write_jwt_without_exact_signed_epoch_is_denied(env, epoch):
    db, _ = env
    old = claims()
    if epoch is None:
        del old["browser_action_epoch"]
    else:
        old["browser_action_epoch"] = epoch
    with pytest.raises(HTTPException) as denied:
        await write(db, signed(old))
    assert denied.value.status_code == 401


@pytest.mark.asyncio
@pytest.mark.parametrize("parent", (None, True, "123", 0, -1, 2**62))
async def test_write_grant_requires_valid_signed_parent_epoch(env, parent):
    db, _ = env
    value = claims(parent_issued_us=parent)
    with pytest.raises(HTTPException) as denied:
        await write(db, signed(value))
    assert denied.value.status_code == 401


@pytest.mark.asyncio
async def test_revoked_parent_jti_cannot_be_replayed_as_new_grant(env):
    db, redis = env
    value = claims()
    redis.values[f"revoked_jti:{value['parent_jti']}"] = "1"
    with pytest.raises(HTTPException) as denied:
        await write(db, signed(value))
    assert denied.value.status_code == 401
    del value["parent_jti"]
    with pytest.raises(HTTPException) as missing:
        await write(db, signed(value))
    assert missing.value.status_code == 401


@pytest.mark.asyncio
async def test_parent_marker_boundary_and_redis_failure(env):
    db, redis = env
    value = claims()
    # Equality is not pre-revocation: the marker comparison uses a strict
    # earlier-than boundary, allowing credentials issued at the marker epoch.
    redis.values[f"revoked_user:{OWNER}"] = str(value["parent_issued_us"])
    await write(db, signed(value))
    value["parent_issued_us"] -= 1
    with pytest.raises(HTTPException) as denied:
        await write(db, signed(value))
    assert denied.value.status_code == 401
    redis.error = True
    with pytest.raises(HTTPException) as unavailable:
        await write(db, signed(value))
    assert unavailable.value.status_code == 503


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


def test_password_login_proof_is_desktop_only_and_not_on_refresh_style_token(env, monkeypatch):
    monkeypatch.setattr("services.crypto.sign_token", signed)
    verified_login, _ = create_access_token(OWNER, UserRole.user, browser_verified=True)
    silent_refresh, _ = create_access_token(OWNER, UserRole.user)
    assert verified(verified_login)["browser_verified_at_us"] == verified(verified_login)["iat_us"]
    assert "browser_verified_at_us" not in verified(silent_refresh)
    with pytest.raises(ValueError, match="Only directly authenticated desktop"):
        create_access_token(OWNER, UserRole.user, client_id=MOBILE_CLIENT_ID, device_id=DEVICE, browser_verified=True)


@pytest.mark.asyncio
async def test_website_access_token_independent_of_login_method(env):
    db, _ = env
    browser_claims = {
        key: value
        for key, value in claims("access").items()
        if key
        not in ("aud", "scope", "device_id", "client_id", "owner_generation", "server_id", "project_id", "cohort")
    }
    browser_claims["browser_verified_at_us"] = browser_claims["iat_us"]

    principal = await F.authorize_browser_approval(
        request("POST", "write-approval"), "Bearer " + signed(browser_claims), db
    )
    assert principal.user.id == OWNER


@pytest.mark.asyncio
async def test_silent_refresh_style_desktop_token_can_identify_browser_owner(env):
    db, _ = env
    # Authentication identifies the owner; separate action proof is mandatory at the HTTP boundary.
    desktop = signed(
        {
            key: value
            for key, value in claims("access").items()
            if key
            not in ("aud", "scope", "device_id", "client_id", "owner_generation", "server_id", "project_id", "cohort")
        }
    )
    principal = await F.authorize_browser_approval(request("POST", "write-approval"), "Bearer " + desktop, db)
    assert principal.user.id == OWNER


@pytest.mark.asyncio
async def test_browser_same_owner_challenge_approval_and_one_use_grant(env):
    db, _ = env
    read = await F.authorize_follow_read(request("POST", "write-authorization"), "Bearer " + read_claims(), db)
    code = await F.create_challenge(db, read)
    assert 20 <= len(code) <= 64
    browser_claims = {
        k: v
        for k, v in claims("access").items()
        if k not in ("aud", "scope", "device_id", "client_id", "owner_generation", "server_id", "project_id", "cohort")
    }
    browser_claims["browser_verified_at_us"] = browser_claims["iat_us"]
    browser_token = signed(browser_claims)
    browser = await F.authorize_browser_approval(request("POST", "write-approval"), "Bearer " + browser_token, db)
    old_claims = verified(browser_token)
    old_claims["iat"] -= 301
    old_claims["iat_us"] -= 301_000_000
    old_claims["browser_verified_at_us"] -= 301_000_000
    assert (
        await F.authorize_browser_approval(request("POST", "write-approval"), "Bearer " + signed(old_claims), db)
    ).user.id == OWNER
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
    # The older helper predates browser-action proof and must not produce an
    # accepted post-safety-stop grant, even when its approval row was consumed.
    with pytest.raises(HTTPException) as denied:
        await write(db, grant)
    assert denied.value.status_code == 401
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
