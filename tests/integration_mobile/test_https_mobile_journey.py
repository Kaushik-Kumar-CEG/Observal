# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Opt-in *real HTTPS* disposable Android-cohort API acceptance (never CI/prod).

Only run after Android accepts v1.2 and the isolated synthetic read gate is
explicitly opened. Read protected account files out of band; never log tokens.
MOBILE_INTEGRATION_HTTPS=1 requires MOBILE_TEST_CA, MOBILE_TEST_ACCOUNTS,
MOBILE_TEST_ORDINARY and MOBILE_TEST_FIXTURE. Origin must be HTTPS loopback.
"""

import json
import os
import uuid
from pathlib import Path
from urllib.parse import urlparse

import httpx
import pytest

pytestmark = pytest.mark.skipif(os.getenv("MOBILE_INTEGRATION_HTTPS") != "1", reason="isolated HTTPS test only")


def _file(name: str) -> dict:
    path = Path(os.environ[name])
    if path.stat().st_mode & 0o077:
        raise AssertionError("Test credential/fixture file must not be group or world accessible")
    return json.loads(path.read_text())


async def _mobile_pair(client: httpx.AsyncClient, account: dict) -> dict:
    challenge = await client.post("/api/v1/auth/device/authorize", json={"client_id": "observal-mobile"})
    assert challenge.status_code == 200
    data = challenge.json()
    assert data["verification_origins"] == [str(client.base_url).rstrip("/")]
    assert data["verification_uri_complete"].startswith(data["verification_origins"][0] + "/device?")
    browser = await client.post("/api/v1/auth/login", json={"email": account["email"], "password": account["password"]})
    assert browser.status_code == 200
    confirmed = await client.post(
        "/api/v1/auth/device/confirm",
        headers={"Authorization": "Bearer " + browser.json()["access_token"]},
        json={"user_code": data["user_code"]},
    )
    assert confirmed.status_code == 200
    redeemed = await client.post(
        "/api/v1/auth/device/token",
        json={"device_code": data["device_code"], "grant_type": "urn:ietf:params:oauth:grant-type:device_code"},
    )
    assert redeemed.status_code == 200
    pair = redeemed.json()
    assert (pair["token_type"], pair["client_id"], pair["audience"], pair["scope"]) == (
        "bearer",
        "observal-mobile",
        "observal-mobile-activity-v1",
        "mobile:read",
    )
    bearer = {"Authorization": "Bearer " + pair["access_token"]}
    proof = await client.get("/api/v1/auth/mobile/credential", headers=bearer)
    assert proof.status_code == 200 and proof.json()["subject_id"] == account["id"]
    assert proof.json()["device_id"]
    legacy = await client.get("/api/v1/auth/whoami", headers=bearer)
    assert legacy.status_code in (401, 403)
    return pair


@pytest.mark.asyncio
async def test_isolated_https_two_scopes_two_components_one_child_root():
    maintainer, ordinary, fixture = (
        _file(key) for key in ("MOBILE_TEST_ACCOUNTS", "MOBILE_TEST_ORDINARY", "MOBILE_TEST_FIXTURE")
    )
    origin = os.environ["MOBILE_TEST_ORIGIN"]
    parsed = urlparse(origin)
    assert parsed.scheme == "https" and parsed.hostname in ("localhost", "127.0.0.1")
    assert parsed.path in ("", "/") and not (parsed.username or parsed.password or parsed.query or parsed.fragment)
    assert fixture["maintainer_id"] == maintainer["id"] and fixture["actor_id"] == ordinary["id"]
    assert fixture["marker"] == "synthetic-mobile-https-v1"
    async with httpx.AsyncClient(
        base_url=origin,
        verify=os.environ["MOBILE_TEST_CA"],
        timeout=30,
        headers={"User-Agent": "Observal-Android-Isolated/1.0"},
    ) as client:
        assert (await client.get("/readyz")).status_code == 200
        maintainer_pair = await _mobile_pair(client, maintainer)
        admin = {"Authorization": "Bearer " + maintainer_pair["access_token"]}
        caps = await client.get("/api/v1/mobile-activity/v1/capabilities", headers=admin)
        assert caps.status_code == 200 and caps.json()["synthetic_test_cohort"] is True
        assert caps.json()["trace_headlines"] is False and caps.json()["viewer_id"] == maintainer["id"]
        batch = await client.post(
            "/api/v1/mobile-activity/v1/people/summaries",
            headers=admin,
            json={"subject_ids": [maintainer["id"], ordinary["id"]], "period": "1w"},
        )
        assert batch.status_code == 200
        author, subject = batch.json()["items"]
        assert author["author_usage"]["value"] == subject["user_usage"]["value"] == 1
        assert author["author_usage"]["status"] == subject["user_usage"]["status"] == "partial"
        assert author["author_usage"]["coverage"]["eligible_sessions"] is None
        assert author["author_revision"] != subject["user_revision"]
        query = {
            "period": "1w",
            "window_anchor": batch.json()["window_anchor"],
            "expected_revision": author["author_revision"],
        }
        detail_base = f"/api/v1/mobile-activity/v1/people/{maintainer['id']}/author/components"
        page = await client.get(detail_base, headers=admin, params=query)
        assert page.status_code == 200, (
            page.status_code,
            [(item.get("loc"), item.get("type")) for item in page.json()["detail"]]
            if isinstance(page.json().get("detail"), list)
            else page.json().get("detail"),
            len(query["window_anchor"]),
            len(query["expected_revision"]),
        )
        assert page.json()["complete"] is True
        assert len(page.json()["items"]) == 2
        ids = {r["component_id"] for r in page.json()["items"]}
        assert ids == set(fixture["component_ids"])
        assert {r["component_traces"]["value"] for r in page.json()["items"]} == {1}
        assert sum(r["mcp_calls"]["value"] for r in page.json()["items"]) == 40
        for row in page.json()["items"]:
            got = await client.get(f"{detail_base}/mcp/{row['component_id']}", headers=admin, params=query)
            assert got.status_code == 200 and got.json()["component"] == row
            assert got.json()["window"] == page.json()["window"]
        ordinary_pair = await _mobile_pair(client, ordinary)
        member = {"Authorization": "Bearer " + ordinary_pair["access_token"]}
        mixed = await client.post(
            "/api/v1/mobile-activity/v1/people/summaries",
            headers=member,
            json={"subject_ids": [ordinary["id"], maintainer["id"]], "period": "1w"},
        )
        assert mixed.status_code == 200
        own, denied = mixed.json()["items"]
        assert own["user_usage"]["value"] == 1 and own["author_usage"] == {"status": "restricted"}
        assert denied["author_usage"] == denied["user_usage"] == {"status": "restricted"}
        user_page = await client.get(
            f"/api/v1/mobile-activity/v1/people/{ordinary['id']}/user/components",
            headers=member,
            params={
                "period": "1w",
                "window_anchor": mixed.json()["window_anchor"],
                "expected_revision": own["user_revision"],
            },
        )
        assert user_page.status_code == 200 and user_page.json()["complete"]
        assert {item["component_id"] for item in user_page.json()["items"]} == ids
        assert {item["component_traces"]["value"] for item in user_page.json()["items"]} == {1}
        for row in user_page.json()["items"]:
            detail = await client.get(
                f"/api/v1/mobile-activity/v1/people/{ordinary['id']}/user/components/mcp/{row['component_id']}",
                headers=member,
                params={
                    "period": "1w",
                    "window_anchor": mixed.json()["window_anchor"],
                    "expected_revision": own["user_revision"],
                },
            )
            assert detail.status_code == 200 and detail.json()["component"] == row
        fully_denied = await client.post(
            "/api/v1/mobile-activity/v1/people/summaries",
            headers=member,
            json={"subject_ids": [str(uuid.uuid4())], "period": "1w"},
        )
        assert fully_denied.status_code == 403 and fully_denied.content == b""
        rotated = await client.post(
            "/api/v1/auth/token/refresh", json={"refresh_token": ordinary_pair["refresh_token"]}
        )
        assert rotated.status_code == 200
        replay = await client.post("/api/v1/auth/token/refresh", json={"refresh_token": ordinary_pair["refresh_token"]})
        assert replay.status_code == 401
        new_member = {"Authorization": "Bearer " + rotated.json()["access_token"]}
        assert (await client.get("/api/v1/auth/mobile/credential", headers=new_member)).status_code == 200
        logout = await client.post(
            "/api/v1/auth/mobile/logout", headers=new_member, json={"refresh_token": rotated.json()["refresh_token"]}
        )
        assert logout.status_code == 200
        assert (await client.get("/api/v1/auth/mobile/credential", headers=new_member)).status_code == 401
        admin_logout = await client.post(
            "/api/v1/auth/mobile/logout", headers=admin, json={"refresh_token": maintainer_pair["refresh_token"]}
        )
        assert admin_logout.status_code == 200
