# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Normal browser challenges require a separate one-use action for each mutation."""

import uuid
from types import SimpleNamespace

import jwt
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from api.deps import get_db
from api.routes import mobile_follow_browser as browser
from api.routes import mobile_follow_write as write
from services import mobile_follow_auth as auth
from services import mobile_follow_browser_action as proof
from services import mobile_follow_enablement as gate


class Redis:
    def __init__(self):
        self.data = {}

    async def set(self, key, value, *, ex, nx):
        assert ex == 120 and nx
        self.data[key] = value
        return True

    async def eval(self, script, numkeys, key, binding):
        if self.data.get(key) != binding:
            return 0
        del self.data[key]
        return 1


def test_normal_http_challenge_does_not_open_consent_or_phone_approval(monkeypatch):
    account = uuid.uuid4()
    jti = uuid.uuid4()
    redis = Redis()
    monkeypatch.setattr(proof, "get_redis", lambda: redis)

    async def setting(key):
        return "https://observal.example" if key in ("deployment.public_url", "deployment.frontend_url") else None

    async def user(payload, db, *, device_id):
        assert payload["sub"] == str(account) and device_id is None
        return SimpleNamespace(id=account)

    async def identity(db):
        return uuid.uuid4()

    async def cohort(db, user, server):
        return "live"

    def decode(token, *, allow_mobile=False):
        if token == "web":
            return {"sub": str(account), "jti": str(jti), "type": "access"}
        raise jwt.InvalidTokenError("phone/refresh/write tokens are not browser access")

    monkeypatch.setattr(browser.settings, "get", setting)
    monkeypatch.setattr(browser.settings, "get_sync", lambda key: "https://observal.example")
    monkeypatch.setattr(browser, "decode_access_token", decode)
    monkeypatch.setattr(auth, "_account", user)
    monkeypatch.setattr(auth, "_identity", identity)
    monkeypatch.setattr(auth, "_cohort", cohort)

    async def approve_principal(request, authorization, db):
        if authorization != "Bearer web":
            from fastapi import HTTPException

            raise HTTPException(401)
        return auth.FollowPrincipal(
            SimpleNamespace(id=account),
            None,
            uuid.uuid4(),
            auth.PROJECT,
            "live",
            1,
            {"sub": str(account), "jti": str(jti)},
        )

    approved = []

    async def approve(db, principal, code, *, action_proven=False):
        approved.append((code, action_proven))

    async def browser_key(request, authorization, db, *, consent=False):
        principal = await approve_principal(request, authorization, db)
        request.state.browser_follow_principal = principal
        return SimpleNamespace()

    consents = []

    async def accept(db, key, **kwargs):
        consents.append(kwargs)
        return {"status": "available", "owner_generation": 2}

    monkeypatch.setattr(auth, "authorize_browser_approval", approve_principal)
    monkeypatch.setattr(auth, "approve_challenge", approve)
    monkeypatch.setattr(write, "_browser", browser_key)
    monkeypatch.setattr(write.privacy, "accept_consent", accept)
    monkeypatch.setattr(write, "consume_browser_action", proof.consume)
    app = FastAPI()
    app.include_router(browser.router, dependencies=[Depends(gate.require_user_verifying_approval)])
    app.include_router(write.router, dependencies=[Depends(gate.require_user_verifying_mutation)])

    async def commit():
        pass

    async def db_session():
        yield SimpleNamespace(commit=commit)

    app.dependency_overrides[get_db] = db_session
    root = "/api/v1/mobile-follow-sync/v1"
    with TestClient(app) as client:
        headers = {"Authorization": "Bearer web", "Origin": "https://observal.example"}
        missing = client.get(root + "/browser-action-challenge?action=consent", headers={"Authorization": "Bearer web"})
        assert missing.status_code == 403
        phone = client.get(
            root + "/browser-action-challenge?action=consent", headers={**headers, "Authorization": "Bearer phone"}
        )
        assert phone.status_code == 401
        challenge = client.get(root + "/browser-action-challenge?action=consent", headers=headers)
        assert challenge.status_code == 200
        nonce = challenge.json()["nonce"]
        assert len(nonce) == 43
        before = dict(redis.data)
        consent_body = {"consent": True, "consent_id": str(uuid.uuid4()), "owner_generation": 1}
        approval_body = {"user_code": "a" * 32, "approve": True}
        for path, body in (("consent", consent_body), ("write-approval", approval_body)):
            denied = client.post(root + "/" + path, headers=headers, json=body)
            assert denied.status_code == 403
        assert redis.data == before
        # Wrong action, wrong JWT, then successful consent and replay across requests.
        for action_headers in (
            {**headers, "X-Observal-Browser-Action": nonce},
            {**headers, "Authorization": "Bearer phone", "X-Observal-Browser-Action": nonce},
        ):
            denied = client.post(root + "/write-approval", headers=action_headers, json=approval_body)
            assert denied.status_code in (401, 403)
        assert (
            client.post(
                root + "/consent", headers={**headers, "X-Observal-Browser-Action": nonce}, json=consent_body
            ).status_code
            == 200
        )
        assert (
            client.post(
                root + "/consent", headers={**headers, "X-Observal-Browser-Action": nonce}, json=consent_body
            ).status_code
            == 403
        )
        assert len(consents) == 1
        approval_nonce = client.get(root + "/browser-action-challenge?action=write-approval", headers=headers).json()[
            "nonce"
        ]
        assert (
            client.post(
                root + "/write-approval",
                headers={**headers, "X-Observal-Browser-Action": approval_nonce},
                json=approval_body,
            ).status_code
            == 200
        )
        assert approved == [("a" * 32, True)]
