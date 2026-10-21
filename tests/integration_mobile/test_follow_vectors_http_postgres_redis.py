# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Named v105 vector replay against the dormant real HTTP routers and disposable PG/Redis.

This is NOT an Android client conformance suite. Only REPLAYED is counted as live
coverage. Every other vector has an explicit, individually identified gap; no
xfail/skip or schema-only validation is counted as an executed vector.
"""

import asyncio
import json
import multiprocessing
import os
import socket
import uuid
from pathlib import Path

import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine
from test_follow_http_postgres_redis import (
    REDIS_URL,
    ROOT,
    _serve,
    bearer,
    browser,
    validate_contract,
)
from test_follow_http_postgres_redis import (
    scratch as _scratch_fixture,  # noqa: F401 — registered shared disposable DB fixture
)

from models.user import UserRole
from services.jwt_service import create_access_token

VECTORS = json.loads(
    (Path(__file__).resolve().parents[2] / "contracts/mobile-activity-v1/follow-sync-v105-vectors.json").read_text()
)["cases"]
BY_NAME = {case["name"]: case for case in VECTORS}

# Ordered: each step depends on the real durable result of its predecessors.
REPLAYED_WITHDRAWAL = (
    "phone_a_withdraw_without_write_grant_denied",
    "phone_b_mobile_read_cannot_restore_opt_in_after_withdrawal",
    "phone_b_cannot_mint_new_grant_during_opt_out",
    "withdrawal_denies_snapshot_not_empty",
    "withdrawal_denies_changes_not_empty",
    "withdrawal_denies_export_not_empty",
)

REPLAYED = (
    "availability_fresh_same_issuer_v12_proof",
    "phone_a_browser_sees_consent_state_before_initial_disclosure",
    "opt_in_after_disclosure_generation_7",
    "phone_b_bound_browser_challenge",
    "second_phone_cannot_mint_write_before_browser_approval",
    "mobile_read_cannot_self_approve",
    "browser_approves_only_phone_b",
    "phone_b_write_grant_binds_generation",
    "read_only_mobile_cannot_write",
    "phone_a_already_available_new_consent_id_cannot_invalidate_follows",
    "unknown_operation_not_proof_of_no_commit",
    "snapshot_limit_1_denied_before_lease",
    "export_limit_50_denied_before_lease",
    "changes_limit_1_denied_before_lease",
    "over_js_safe_after_revision_query_rejected",
    "phone_b_prepares_remove_all_gen7",
    "phone_b_remove_all_atomically_advances_to_8",
    "phone_b_lost_202_old_write_grant_cannot_replay",
    "old_change_checkpoint_after_generation_advance_conflicts",
    "phone_b_lost_202_read_authenticated_nonce_lookup",
)


# A reason is a *gap*, not an assertion that the fixture was executed. Including
# the name prevents a generic reason from hiding two different missing scenarios.
def gap(case):
    name = case["name"]
    if case.get("invalid_response_schema") or case.get("invalid_client_cross_field"):
        barrier = "requires a deliberately malformed server reply and Android rejection, not a real-router success"
    elif case["method"] == "none" or (case.get("client_result") and "local" in name):
        barrier = "requires Android local encrypted state or offline client behavior, absent from HTTP harness"
    elif case.get("raw_body") is not None or "old_server" in name:
        barrier = "requires a separately proven older issuer/server, not the v105 scratch router"
    elif case.get("fixture"):
        barrier = f"requires unseeded scenario ({case['fixture']}); no matching live response validated"
    elif "cursor=" in case.get("path", ""):
        barrier = "requires a genuine signed cursor and matching prior pinned lease, not the literal vector placeholder"
    elif case.get("status") == 0:
        barrier = "requires intercepted lost network acknowledgement and durable lookup, not an HTTP status zero"
    else:
        barrier = (
            f"requires {case['credential']} with matching generation/owner/state for "
            f"{case['method']} {case['path']} => {case['status']}; no matching live response validated"
        )
    return f"{name}: {barrier}"


GAPS = {case["name"]: gap(case) for case in VECTORS if case["name"] not in REPLAYED + REPLAYED_WITHDRAWAL}


def test_vector_accounting_is_explicit_not_fake_coverage():
    assert len(VECTORS) == 146
    assert len(BY_NAME) == 146, "duplicate vector names cannot be accounted for"
    assert len(REPLAYED + REPLAYED_WITHDRAWAL) == len(set(REPLAYED + REPLAYED_WITHDRAWAL))
    assert set(REPLAYED + REPLAYED_WITHDRAWAL) | set(GAPS) == set(BY_NAME)
    assert not set(REPLAYED + REPLAYED_WITHDRAWAL) & set(GAPS)
    assert len(set(GAPS.values())) == len(GAPS), "each unimplemented case needs an individual reason"
    assert all(reason and len(reason.split(": ", 1)[-1]) > 25 for reason in GAPS.values())


@pytest.mark.skipif(os.getenv("MOBILE_FOLLOW_HTTP_SCRATCH") != "1", reason="requires disposable PG15440 and Redis16380")
@pytest.mark.asyncio
async def test_named_vectors_replayed_over_real_http(_scratch_fixture):  # noqa: F811 — pytest fixture injection
    url, key_dir, _, owner, _ = _scratch_fixture
    ctx = multiprocessing.get_context("spawn")
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(128)
    worker = ctx.Process(target=_serve, args=(sock, url, REDIS_URL, key_dir))
    worker.start()
    try:
        async with httpx.AsyncClient(
            base_url=f"http://127.0.0.1:{sock.getsockname()[1]}",
            timeout=15,
            event_hooks={"response": [validate_contract]},
        ) as client:
            phone_a, _ = create_access_token(
                owner, UserRole.super_admin, client_id="observal-mobile", device_id="phone-a"
            )
            phone_b, _ = create_access_token(
                owner, UserRole.super_admin, client_id="observal-mobile", device_id="phone-b"
            )
            desktop, _ = create_access_token(owner, UserRole.super_admin)
            headers = {
                "mobile:read": bearer(phone_a),
                "mobile:read_phone_b": bearer(phone_b),
                "browser": browser(desktop),
            }
            for _ in range(100):
                try:
                    if (await client.get(ROOT + "/availability", headers=bearer(phone_a))).status_code == 200:
                        break
                except httpx.TransportError:
                    pass
                assert worker.is_alive(), worker.exitcode
                await asyncio.sleep(0.1)
            else:
                pytest.fail("scratch HTTP worker did not become ready")

            # The vector's synthetic generation 6/7/8 maps to fresh DB 1/2/3;
            # UUIDs in vector bodies remain real caller-supplied IDs.
            challenge = grant = nonce = removal = None
            seen = []
            for name in REPLAYED:
                case = BY_NAME[name]
                request = dict(case.get("request") or {})
                for generation_field in ("owner_generation", "original_owner_generation"):
                    if generation_field in request:
                        request[generation_field] -= 5
                path = (
                    case["path"]
                    .replace("owner_generation=12", "owner_generation=2")
                    .replace("owner_generation=10", "owner_generation=2")
                    .replace("owner_generation=7", "owner_generation=2")
                )
                if name == "phone_b_prepares_remove_all_gen7":
                    auth = bearer(grant)
                elif name in (
                    "phone_b_remove_all_atomically_advances_to_8",
                    "phone_b_lost_202_old_write_grant_cannot_replay",
                ):
                    auth = bearer(grant)
                    request["nonce"] = nonce
                elif name == "phone_b_lost_202_read_authenticated_nonce_lookup":
                    auth = bearer(phone_b)
                    request["nonce"] = nonce
                elif name == "mobile_read_cannot_self_approve":
                    auth = bearer(phone_a)
                    request["user_code"] = challenge["user_code"]
                elif name == "browser_approves_only_phone_b":
                    auth = headers["browser"]
                    request["user_code"] = challenge["user_code"]
                elif case["credential"].startswith("browserBearer"):
                    auth = headers["browser"]
                elif "phone_b" in case["credential"]:
                    auth = headers["mobile:read_phone_b"]
                else:
                    auth = headers["mobile:read"]
                response = await client.request(
                    case["method"],
                    ROOT + path.removeprefix("/mobile-follow-sync/v1"),
                    headers=auth,
                    json=request if "request" in case else None,
                )
                assert response.status_code == case["status"], (name, response.status_code, response.text[:500])
                body = response.json()
                expected = dict(case["body"])
                if "owner_generation" in expected and name != "availability_fresh_same_issuer_v12_proof":
                    expected["owner_generation"] -= 5
                if name == "availability_fresh_same_issuer_v12_proof":
                    expected.update(server_id=body["server_id"], viewer_id=str(owner), cohort="synthetic")
                if name == "phone_b_bound_browser_challenge":
                    challenge = body
                    expected = {"owner_generation": 2, "verification_origins": ["https://127.0.0.1:19443"]}
                if name == "phone_b_write_grant_binds_generation":
                    grant = body["access_token"]
                    expected["access_token"] = grant
                if name == "phone_b_prepares_remove_all_gen7":
                    nonce = body["nonce"]
                    expected = {"owner_generation": 2, "nonce": nonce}
                if name == "phone_b_remove_all_atomically_advances_to_8":
                    removal = body
                    expected["removal_id"] = removal["removal_id"]
                if name == "phone_b_lost_202_read_authenticated_nonce_lookup":
                    expected["removal_id"] = removal["removal_id"]
                    assert body == removal, name
                for field, value in expected.items():
                    assert body[field] == value, (name, field, body[field], value)
                if name == "phone_b_lost_202_old_write_grant_cannot_replay":
                    assert body == {"error": "unauthorized"}
                seen.append(name)
                if name == "over_js_safe_after_revision_query_rejected":
                    # Extra live analogue, NOT counted as capacity vector 91/98/142:
                    # empty image rather than the vector's 1000 pinned rows.
                    first = await client.get(ROOT + "/snapshot?limit=100", headers=bearer(phone_a))
                    assert first.status_code == 429, first.text
                    retry = first.json()
                    assert retry["error"] == "rate_limited"
                    assert 0 < int(first.headers["Retry-After"]) <= 60
                    assert retry["read_lease_id"] and retry["retry_cursor"]
                    again = await client.get(ROOT + "/snapshot?limit=100", headers=bearer(phone_b))
                    assert again.status_code == 200, again.text
                    assert again.json()["read_lease_id"] == retry["read_lease_id"]
                    page = await client.get(
                        ROOT + "/snapshot",
                        headers=bearer(phone_a),
                        params={"limit": 100, "cursor": retry["retry_cursor"]},
                    )
                    assert page.status_code == 200, page.text
                    assert page.json()["read_lease_id"] == retry["read_lease_id"]
                    assert page.json()["complete"] and page.json()["items"] == []
            assert tuple(seen) == REPLAYED
            # The lost-202 lookup must refer to the persisted fence, not a synthetic response.
            engine = create_async_engine(url)
            try:
                async with engine.connect() as conn:
                    assert (
                        await conn.scalar(
                            text(
                                "SELECT owner_generation FROM mobile_follow_partitions WHERE owner_id=:owner AND cohort='synthetic-author'"
                            ),
                            {"owner": owner},
                        )
                        == 3
                    )
            finally:
                await engine.dispose()
    finally:
        if worker.is_alive():
            worker.terminate()
        worker.join(timeout=10)
        if worker.is_alive():
            worker.kill()
            worker.join(timeout=5)
        sock.close()


@pytest.mark.skipif(os.getenv("MOBILE_FOLLOW_HTTP_SCRATCH") != "1", reason="requires disposable PG15440 and Redis16380")
@pytest.mark.asyncio
async def test_post_withdrawal_named_denials_real_http(_scratch_fixture):  # noqa: F811
    """Persist a browser-authorized withdrawal, then replay frozen denials."""
    url, key_dir, _, owner, _ = _scratch_fixture
    ctx = multiprocessing.get_context("spawn")
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(128)
    worker = ctx.Process(target=_serve, args=(sock, url, REDIS_URL, key_dir))
    worker.start()
    try:
        async with httpx.AsyncClient(
            base_url=f"http://127.0.0.1:{sock.getsockname()[1]}",
            timeout=15,
            event_hooks={"response": [validate_contract]},
        ) as client:
            phone_a, _ = create_access_token(
                owner, UserRole.super_admin, client_id="observal-mobile", device_id="phone-a"
            )
            phone_b, _ = create_access_token(
                owner, UserRole.super_admin, client_id="observal-mobile", device_id="phone-b"
            )
            desktop, _ = create_access_token(owner, UserRole.super_admin)
            for _ in range(100):
                try:
                    if (await client.get(ROOT + "/consent/state", headers=browser(desktop))).status_code == 200:
                        break
                except httpx.TransportError:
                    pass
                assert worker.is_alive(), worker.exitcode
                await asyncio.sleep(0.1)
            else:
                pytest.fail("scratch HTTP worker did not become ready")
            accepted = await client.post(
                ROOT + "/consent",
                headers=browser(desktop),
                json={"consent": True, "consent_id": str(uuid.uuid4()), "owner_generation": 1},
            )
            assert accepted.status_code == 200 and accepted.json()["owner_generation"] == 2
            # First named 401 occurs BEFORE withdrawal, with an actual read-only phone bearer.
            first = BY_NAME[REPLAYED_WITHDRAWAL[0]]
            denied = await client.post(
                ROOT + "/consent/withdraw", headers=bearer(phone_a), json={**first["request"], "owner_generation": 2}
            )
            assert denied.status_code == first["status"] and denied.json() == first["body"]
            withdrawal = await client.post(
                ROOT + "/consent/withdraw",
                headers=browser(desktop),
                json={"confirm": True, "withdrawal_id": str(uuid.uuid4()), "owner_generation": 2},
            )
            assert withdrawal.status_code == 202 and withdrawal.json()["state"] == "pending"
            for name in REPLAYED_WITHDRAWAL[1:]:
                case = BY_NAME[name]
                body = dict(case.get("request") or {})
                if "owner_generation" in body:
                    body["owner_generation"] = 3
                path = case["path"].removeprefix("/mobile-follow-sync/v1")
                # Frozen synthetic generations 8/9 correspond to this fresh DB's 2/3.
                path = path.replace("owner_generation=9", "owner_generation=3")
                auth = bearer(phone_b)
                response = await client.request(
                    case["method"],
                    ROOT + path,
                    headers=auth,
                    json=body if "request" in case else None,
                )
                assert response.status_code == case["status"], (name, response.status_code, response.text[:200])
                assert response.json() == case["body"], name
                if "headers" in case:
                    for header, expected in case["headers"].items():
                        assert response.headers[header] == expected, name
            engine = create_async_engine(url)
            try:
                async with engine.connect() as conn:
                    row = (
                        await conn.execute(
                            text(
                                "SELECT consent_state,removal_state FROM mobile_follow_partitions WHERE owner_id=:owner"
                            ),
                            {"owner": owner},
                        )
                    ).one()
                    assert row == ("withdrawal_pending", "pending"), "503 denials must not count as empty or erased"
            finally:
                await engine.dispose()
    finally:
        if worker.is_alive():
            worker.terminate()
        worker.join(timeout=10)
        if worker.is_alive():
            worker.kill()
            worker.join(timeout=5)
        sock.close()
