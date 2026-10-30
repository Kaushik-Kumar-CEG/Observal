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
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
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
from observal_shared.migration.constants import DEFAULT_PROJECT_ID
from services.jwt_service import create_access_token
from services.mobile_follow_privacy import erase_batch
from services.mobile_follow_store import Partition

VECTORS = json.loads(
    (Path(__file__).resolve().parents[2] / "contracts/mobile-activity-v1/follow-sync-v105-vectors.json").read_text()
)["cases"]
BY_NAME = {case["name"]: case for case in VECTORS}

# Ordered: each step depends on the real durable result of its predecessors.
REPLAYED_WITHDRAWAL = (
    "phone_a_withdraw_without_write_grant_denied",
    "phone_b_mobile_read_cannot_restore_opt_in_after_withdrawal",
    "phone_b_stale_opt_in_during_withdrawal_fenced",
    "phone_b_cannot_mint_new_grant_during_opt_out",
    "withdrawal_denies_snapshot_not_empty",
    "withdrawal_denies_changes_not_empty",
    "withdrawal_denies_export_not_empty",
)

REPLAYED_WITHDRAWAL_STATUS = (
    "phone_a_requests_explicit_consent_withdrawal",
    "phone_a_lost_withdraw_202_idempotent_status",
)

REPLAYED_HISTORY = (
    "phone_a_new_human_choice_new_op_after_gen8_snapshot",
    "phone_b_reads_same_account_snapshot_gen8",
    "history_phone_b_unfollows_after_a_commit",
    "history_a_lost_200_lookup_historical_not_synced",
    "history_a_complete_delta_reconciles_after_lost_200",
    "history_a_full_snapshot_rev2_confirms_not_following",
    "availability_current_revision_after_phone_b_unfollow",
    "over_js_safe_base_revision_rejected_before_number_rounding",
)

REPLAYED_FENCED_HISTORY = (
    "lost_200_lookup_effective_applied_exact",
    "lost_409_lookup_effective_conflict_exact",
    "phone_b_removal_completed",
    "phone_a_alternate_history_lost_200_from_pre_removal_status_redacted",
    "lost_409_after_owner_reset_redacted",
    "old_snapshot_cursor_after_generation_advance_conflicts",
    "phone_a_late_unseen_base0_replay_cannot_resurrect",
    "phone_b_valid_gen10_grant_stale_gen8_intent_conflicts",
    "phone_b_offline_pending_edit_after_withdrawal_revoked",
    "withdrawal_completed_no_follows_or_consent",
    "availability_after_withdrawal_requires_new_disclosure",
    "phone_b_browser_sees_new_generation_before_reconsent",
    "phone_b_stale_prewithdrawal_opt_in_after_phone_a_completion",
    "phone_b_fresh_reconsent_advances_to_10",
    "old_phone_a_gen8_grant_cannot_readd_after_reconsent",
    "owner_only_uuid_export_after_reconsent",
)

REPLAYED = (
    "availability_fresh_same_issuer_v12_proof",
    "denial_401_not_fallback",
    "offline_day_30_old_mobile_proof_denied",
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


# Additional third-wave names are counted only by the independent live HTTP test.
REPLAYED_THIRD = (
    "owner_initial_429_lost_retries_cursorless_without_new_pinned_image",
    "phone_b_cursorless_after_phone_a_lost_first_429_reuses_exact_image",
    "capacity_snapshot_page_1_not_authoritative",
    "capacity_snapshot_page_5_after_restart",
    "capacity_snapshot_page_10_after_one_retry",
    "capacity_export_page_1_is_not_full_export",
    "phone_b_concurrent_export_reuses_phone_a_image",
    "capacity_export_page_10_after_restart_and_429",
    "capacity_changes_first_page_pins_fixed_upper",
    "capacity_changes_page_10_fixed_upper_after_restart_and_new_writes",
    "third_device_after_two_distinct_change_slots_uses_snapshot_fallback",
    "delta_older_than_89_days_falls_back_before_admission",
    "max_safe_json_revision_accepted",
    "revision_increment_at_safe_limit_fails_closed",
    "two_checkpoint_phone_a_changes_pins_upper_1000",
    "two_checkpoint_phone_b_changes_pins_newer_upper_1001",
    "two_checkpoint_phone_a_completes_without_b_starvation",
    "two_checkpoint_phone_b_completes_at_newer_upper",
    "over_1000_change_window_falls_back_before_first_page",
    "capacity_page_at_899_seconds_remains_valid",
    "capacity_lease_at_900_seconds_never_promotes_partial",
    "partial_snapshot_after_24h_must_restart_without_implicit_write",
)


REPLAYED_FIFTH = (
    "phone_b_browser_withdraws_after_last_phone_unlinked",
    "phone_b_browser_checks_erasure_after_last_phone_lost",
    "withdrawal_needs_operator_keeps_fence",
    "conflict_same_person_in_new_generation",
)


REPLAYED_CAPACITY_429 = (
    "capacity_first_page_429_reserves_lease_before_reply",
    "capacity_snapshot_page_10_rate_limited_once",
)

REPLAYED_SIXTH = (
    "independent_101_change_fixture_first_100",
    "independent_101_change_fixture_last_1",
    "phone_b_min_rev2_uses_second_free_snapshot_slot_immediately",
    "owner_budget_released_at_15min_next_first_request_recovers",
    "draft_1000_per_generation_cap_not_lifetime",
)

REPLAYED_SEVENTH = (
    "generation_conflict_409_redacted_no_person_fields",
    "local_1001st_import_is_denied_without_deleting_local",
)


# A reason is a *gap*, not an assertion that the fixture was executed. Including
# the name prevents a generic reason from hiding two different missing scenarios.
# A client-side rejection of a malformed reply cannot be proved by a successful
# real router. Server cases remain engineering gaps even when Android also has
# an associated client_result.
def gap_kind(case):
    if case["method"] == "none" or case.get("invalid_response_schema") or case.get("invalid_client_cross_field"):
        return "Android client/local behavior"
    if case.get("status") == 0:
        return "Android lost-ack/local behavior (durable server lookup separately replayable)"
    if case.get("raw_body") is not None or "old_server" in case["name"]:
        return "older issuer / Android fallback (not the v105 scratch router)"
    return "server replay engineering gap"


def gap(case):
    name = case["name"]
    if name in {
        "erased_subject_cannot_recreate_in_any_generation",
        "phone_a_same_generation_subject_erasure_denies_original_post_replay",
        "subject_erasure_redacts_same_generation_operation_status",
        "capacity_lease_subject_erasure_revokes_all_versions",
    }:
        barrier = (
            "real user deletion closes the global project read gate; frozen follow-specific response requires "
            "completed external purge and legitimate operator requalification, not a manual gate update"
        )
    elif name == "denial_403_not_fallback":
        barrier = (
            "requires a scoped foreign-owner v1.2 credential fixture; a distinct user's own availability "
            "legitimately returns 200, so that attempted HTTP response is NOT counted as replay"
        )
    elif case.get("invalid_response_schema") or case.get("invalid_client_cross_field"):
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
    return f"{name}: [{gap_kind(case)}] {barrier}"


GAPS = {
    case["name"]: gap(case)
    for case in VECTORS
    if case["name"]
    not in REPLAYED
    + REPLAYED_WITHDRAWAL
    + REPLAYED_WITHDRAWAL_STATUS
    + REPLAYED_HISTORY
    + REPLAYED_FENCED_HISTORY
    + REPLAYED_THIRD
    + REPLAYED_CAPACITY_429
    + REPLAYED_FIFTH
    + REPLAYED_SIXTH
    + REPLAYED_SEVENTH
}


def test_vector_accounting_is_explicit_not_fake_coverage():
    assert len(VECTORS) == 146
    assert len(BY_NAME) == 146, "duplicate vector names cannot be accounted for"
    executed = (
        REPLAYED
        + REPLAYED_WITHDRAWAL
        + REPLAYED_WITHDRAWAL_STATUS
        + REPLAYED_HISTORY
        + REPLAYED_FENCED_HISTORY
        + REPLAYED_THIRD
        + REPLAYED_CAPACITY_429
        + REPLAYED_FIFTH
        + REPLAYED_SIXTH
        + REPLAYED_SEVENTH
    )
    assert len(executed) == len(set(executed))
    assert set(executed) | set(GAPS) == set(BY_NAME)
    assert not set(executed) & set(GAPS)
    assert len(set(GAPS.values())) == len(GAPS), "each unimplemented case needs an individual reason"
    assert all(reason and len(reason.split(": ", 1)[-1]) > 25 for reason in GAPS.values())
    assert all(gap_kind(BY_NAME[name]) in reason for name, reason in GAPS.items())


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
            desktop, _ = create_access_token(owner, UserRole.super_admin, browser_verified=True)
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
                if name == "denial_401_not_fallback":
                    expired, _ = create_access_token(
                        owner,
                        UserRole.super_admin,
                        expires_in_minutes=-1,
                        client_id="observal-mobile",
                        device_id="phone-expired",
                    )
                    auth = bearer(expired)
                elif name == "offline_day_30_old_mobile_proof_denied":
                    old, _ = create_access_token(
                        owner,
                        UserRole.super_admin,
                        expires_in_minutes=-30 * 24 * 60,
                        client_id="observal-mobile",
                        device_id="phone-old",
                    )
                    auth = bearer(old)
                elif name == "phone_b_prepares_remove_all_gen7":
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
                if "server_id" in expected:
                    expected.update(server_id=body["server_id"], viewer_id=str(owner), cohort="synthetic")
                    uuid.UUID(body["server_id"])
                if name == "phone_b_bound_browser_challenge":
                    challenge = body
                    assert 20 <= len(body["user_code"]) <= 32 and body["user_code"].isascii()
                    expected.update(
                        user_code=body["user_code"],
                        verification_uri="https://127.0.0.1:19443/follow/approve?code=" + body["user_code"],
                        verification_origins=["https://127.0.0.1:19443"],
                    )
                if name == "phone_b_write_grant_binds_generation":
                    grant = body["access_token"]
                    expected["access_token"] = grant
                if name == "phone_b_prepares_remove_all_gen7":
                    nonce = body["nonce"]
                    assert len(nonce) >= 20
                    expected["nonce"] = nonce
                if name == "phone_b_remove_all_atomically_advances_to_8":
                    removal = body
                    expected["removal_id"] = removal["removal_id"]
                if name == "phone_b_lost_202_read_authenticated_nonce_lookup":
                    expected["removal_id"] = removal["removal_id"]
                    assert body == removal, name
                assert body == expected, (name, body, expected)
                for header, value in case.get("headers", {}).items():
                    assert response.headers[header] == value, name
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
            print("REAL_HTTP_VECTOR_PASS", ",".join(seen))
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
async def test_independent_two_phone_history_vectors_real_http(_scratch_fixture):  # noqa: F811
    """Seed an independent two-device commit/undo history over real HTTP."""
    url, key_dir, _, owner, _ = _scratch_fixture
    subject = BY_NAME[REPLAYED_HISTORY[0]]["request"]["subject_id"]
    engine = create_async_engine(url)
    try:
        async with engine.begin() as conn:
            await conn.execute(
                text(
                    "INSERT INTO users (id,email,username,name,role,created_at) "
                    "VALUES (:id,:email,:username,'Vector subject','user',clock_timestamp())"
                ),
                {"id": subject, "email": "history-subject@scratch.invalid", "username": "history-subject"},
            )
    finally:
        await engine.dispose()
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(128)
    worker = multiprocessing.get_context("spawn").Process(target=_serve, args=(sock, url, REDIS_URL, key_dir))
    worker.start()
    try:
        async with httpx.AsyncClient(
            base_url=f"http://127.0.0.1:{sock.getsockname()[1]}",
            timeout=15,
            event_hooks={"response": [validate_contract]},
        ) as client:
            a, _ = create_access_token(owner, UserRole.super_admin, client_id="observal-mobile", device_id="phone-a")
            b, _ = create_access_token(owner, UserRole.super_admin, client_id="observal-mobile", device_id="phone-b")
            desktop, _ = create_access_token(owner, UserRole.super_admin, browser_verified=True)
            for _ in range(100):
                try:
                    if (await client.get(ROOT + "/availability", headers=bearer(a))).status_code == 200:
                        break
                except httpx.TransportError:
                    pass
                assert worker.is_alive(), worker.exitcode
                await asyncio.sleep(0.1)
            else:
                pytest.fail("scratch HTTP worker did not become ready")
            consent = await client.post(
                ROOT + "/consent",
                headers=browser(desktop),
                json={"consent": True, "consent_id": str(uuid.uuid4()), "owner_generation": 1},
            )
            assert consent.status_code == 200 and consent.json() == {"state": "available", "owner_generation": 2}

            async def approved_grant(phone):
                challenge = await client.post(ROOT + "/write-authorization", headers=bearer(phone))
                assert challenge.status_code == 200, challenge.text
                approval = await client.post(
                    ROOT + "/write-approval",
                    headers=browser(desktop),
                    json={"user_code": challenge.json()["user_code"], "approve": True},
                )
                assert approval.status_code == 200, approval.text
                grant = await client.post(ROOT + "/write-grant", headers=bearer(phone))
                assert grant.status_code == 200, grant.text
                return grant.json()["access_token"]

            grant_a, grant_b = await approved_grant(a), await approved_grant(b)
            server_id = (await client.get(ROOT + "/availability", headers=bearer(a))).json()["server_id"]

            async def replay(name, auth, *, path=None):
                case = BY_NAME[name]
                request = dict(case.get("request") or {})
                if "owner_generation" in request:
                    request["owner_generation"] -= 6  # frozen gen8 -> scratch gen2
                target = path or case["path"].removeprefix("/mobile-follow-sync/v1")
                response = await client.request(
                    case["method"],
                    ROOT + target,
                    headers=bearer(auth),
                    json=request if "request" in case else None,
                )
                assert response.status_code == case["status"], (name, response.status_code, response.text)
                expected = json.loads(json.dumps(case["body"]))
                if "owner_generation" in expected:
                    expected["owner_generation"] -= 6
                if "owner_generation" in expected.get("result", {}):
                    expected["result"]["owner_generation"] -= 6
                if "server_id" in expected:
                    expected.update(server_id=server_id, viewer_id=str(owner), cohort="synthetic")
                if "read_lease_id" in expected:
                    expected["read_lease_id"] = response.json()["read_lease_id"]
                    uuid.UUID(expected["read_lease_id"])
                assert response.json() == expected, (name, response.json(), expected)
                for header, value in case.get("headers", {}).items():
                    assert response.headers[header] == value, name

            await replay(REPLAYED_HISTORY[0], grant_a)

            async def read_page(name, phone, path):
                first = await client.get(ROOT + path, headers=bearer(phone))
                if first.status_code == 429:
                    retry = first.json()
                    assert retry["error"] == "rate_limited" and int(first.headers["Retry-After"]) > 0
                    uuid.UUID(retry["read_lease_id"])
                    path = path.split("?", 1)[0]
                    if name == "history_a_complete_delta_reconciles_after_lost_200":
                        path += "?owner_generation=2&after_revision=0&limit=100&cursor=" + retry["retry_cursor"]
                    else:
                        minimum = (
                            "&min_revision=2" if name == "history_a_full_snapshot_rev2_confirms_not_following" else ""
                        )
                        path += "?limit=100" + minimum + "&cursor=" + retry["retry_cursor"]
                await replay(name, phone, path=path)

            await read_page(REPLAYED_HISTORY[1], b, "/snapshot?limit=100")
            await replay(REPLAYED_HISTORY[2], grant_b)
            await replay(REPLAYED_HISTORY[3], a)
            await read_page(REPLAYED_HISTORY[4], a, "/changes?owner_generation=2&after_revision=0&limit=100")
            await read_page(REPLAYED_HISTORY[5], a, "/snapshot?limit=100&min_revision=2")
            await replay(REPLAYED_HISTORY[6], a)
            await replay(REPLAYED_HISTORY[7], grant_b)
            engine = create_async_engine(url)
            try:
                async with engine.connect() as conn:
                    assert (
                        await conn.scalar(
                            text(
                                "SELECT current_revision FROM mobile_follow_partitions WHERE owner_id=:owner "
                                "AND cohort='synthetic-author'"
                            ),
                            {"owner": owner},
                        )
                        == 2
                    )
            finally:
                await engine.dispose()
            print("REAL_HTTP_VECTOR_PASS", ",".join(REPLAYED_HISTORY))
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
            desktop, _ = create_access_token(owner, UserRole.super_admin, browser_verified=True)
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
            request_case = BY_NAME["phone_a_requests_explicit_consent_withdrawal"]
            withdrawal = await client.post(
                ROOT + "/consent/withdraw",
                headers=browser(desktop),
                json={**request_case["request"], "owner_generation": 2},
            )
            assert withdrawal.status_code == request_case["status"]
            assert withdrawal.json() == {**request_case["body"], "owner_generation": 3}
            status_case = BY_NAME["phone_a_lost_withdraw_202_idempotent_status"]
            status = await client.get(
                ROOT + status_case["path"].removeprefix("/mobile-follow-sync/v1"), headers=bearer(phone_a)
            )
            assert status.status_code == status_case["status"]
            assert status.json() == {**status_case["body"], "owner_generation": 3}
            for name in REPLAYED_WITHDRAWAL[1:]:
                case = BY_NAME[name]
                body = dict(case.get("request") or {})
                if "owner_generation" in body:
                    body["owner_generation"] = 2 if name == "phone_b_stale_opt_in_during_withdrawal_fenced" else 3
                path = case["path"].removeprefix("/mobile-follow-sync/v1")
                # Frozen synthetic generations 8/9 correspond to this fresh DB's 2/3.
                path = path.replace("owner_generation=9", "owner_generation=3")
                auth = browser(desktop) if name == "phone_b_stale_opt_in_during_withdrawal_fenced" else bearer(phone_b)
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
            print(
                "REAL_HTTP_VECTOR_PASS",
                ",".join(
                    (
                        REPLAYED_WITHDRAWAL[0],
                        *REPLAYED_WITHDRAWAL_STATUS,
                        *REPLAYED_WITHDRAWAL[1:],
                    )
                ),
            )
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
async def test_fenced_history_and_reconsent_vectors_real_http(_scratch_fixture):  # noqa: F811
    """Two real devices, committed operations, removal, completed withdrawal and re-consent."""
    url, key_dir, _, owner, _ = _scratch_fixture
    engine = create_async_engine(url)
    subject = BY_NAME["lost_200_lookup_effective_applied_exact"]["body"]["result"]["subject_id"]
    second_subject = "55555555-5555-4555-8555-555555555555"
    try:
        async with engine.begin() as conn:
            for i, uid in enumerate((subject, second_subject)):
                await conn.execute(
                    text(
                        "INSERT INTO users (id,email,username,name,role,created_at) "
                        "VALUES (:id,:email,:username,'Replay subject','user',clock_timestamp())"
                    ),
                    {"id": uid, "email": f"fenced-{i}@scratch.invalid", "username": f"fenced-{i}"},
                )
            server_id = await conn.scalar(text("SELECT server_id FROM mobile_server_identity WHERE singleton=true"))
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        sock.listen(128)
        worker = multiprocessing.get_context("spawn").Process(target=_serve, args=(sock, url, REDIS_URL, key_dir))
        worker.start()
        try:
            async with httpx.AsyncClient(
                base_url=f"http://127.0.0.1:{sock.getsockname()[1]}",
                timeout=15,
                event_hooks={"response": [validate_contract]},
            ) as client:
                a, _ = create_access_token(
                    owner, UserRole.super_admin, client_id="observal-mobile", device_id="phone-a"
                )
                b, _ = create_access_token(
                    owner, UserRole.super_admin, client_id="observal-mobile", device_id="phone-b"
                )
                desktop, _ = create_access_token(owner, UserRole.super_admin, browser_verified=True)
                for _ in range(100):
                    try:
                        if (await client.get(ROOT + "/availability", headers=bearer(a))).status_code == 200:
                            break
                    except httpx.TransportError:
                        pass
                    assert worker.is_alive(), worker.exitcode
                    await asyncio.sleep(0.1)
                else:
                    pytest.fail("scratch HTTP worker did not become ready")

                async def call(path, auth, *, method="GET", body=None):
                    return await client.request(method, ROOT + path, headers=auth, json=body)

                async def replay(name, auth, *, generation=None, request_generation=None, path=None):
                    case = BY_NAME[name]
                    request = dict(case.get("request") or {})
                    if request_generation is not None:
                        request["owner_generation"] = request_generation
                    target = path or case["path"].removeprefix("/mobile-follow-sync/v1")
                    response = await call(
                        target, auth, method=case["method"], body=request if "request" in case else None
                    )
                    if name == "owner_only_uuid_export_after_reconsent" and response.status_code == 429:
                        admitted = response.json()
                        assert admitted["error"] == "rate_limited" and int(response.headers["Retry-After"]) > 0
                        uuid.UUID(admitted["read_lease_id"])
                        response = await call(target + "&cursor=" + admitted["retry_cursor"], auth)
                        assert response.json()["read_lease_id"] == admitted["read_lease_id"]
                    assert response.status_code == case["status"], (name, response.status_code, response.text)
                    expected = json.loads(json.dumps(case["body"]))
                    if generation is not None and "owner_generation" in expected:
                        expected["owner_generation"] = generation
                    if "original_owner_generation" in expected.get("result", {}):
                        expected["result"]["original_owner_generation"] = 2
                        expected["result"]["owner_generation"] = generation
                    if "owner_generation" in expected.get("result", {}):
                        expected["result"]["owner_generation"] = generation
                    if "server_id" in expected:
                        expected.update(server_id=str(server_id), viewer_id=str(owner), cohort="synthetic")
                    if "removal_id" in expected:
                        expected["removal_id"] = removed.json()["removal_id"]
                    if "read_lease_id" in expected:
                        expected["read_lease_id"] = response.json()["read_lease_id"]
                        uuid.UUID(expected["read_lease_id"])
                    if name == "owner_only_uuid_export_after_reconsent":
                        # Two actual privacy fences (removal + withdrawal) advanced this scratch floor.
                        expected["erasure_floor"] = 2
                    assert response.json() == expected, (name, response.json(), expected)
                    for header, value in case.get("headers", {}).items():
                        assert response.headers[header] == value, name
                    seen.append(name)

                async def grant(phone):
                    challenge = await call("/write-authorization", bearer(phone), method="POST")
                    assert challenge.status_code == 200, challenge.text
                    approval = await call(
                        "/write-approval",
                        browser(desktop),
                        method="POST",
                        body={"user_code": challenge.json()["user_code"], "approve": True},
                    )
                    assert approval.status_code == 200, approval.text
                    issued = await call("/write-grant", bearer(phone), method="POST")
                    assert issued.status_code == 200, issued.text
                    return issued.json()["access_token"]

                seen = []
                consent = await call(
                    "/consent",
                    browser(desktop),
                    method="POST",
                    body={"consent": True, "consent_id": str(uuid.uuid4()), "owner_generation": 1},
                )
                assert consent.status_code == 200 and consent.json() == {"state": "available", "owner_generation": 2}
                grant_a, grant_b = await grant(a), await grant(b)
                first = dict(
                    BY_NAME["phone_a_new_human_choice_new_op_after_gen8_snapshot"]["request"], owner_generation=2
                )
                applied = await call("/operations", bearer(grant_a), method="POST", body=first)
                assert applied.status_code == 200 and applied.json()["revision"] == 1
                conflict = dict(
                    BY_NAME["conflict_same_person_in_new_generation"]["request"],
                    owner_generation=2,
                    subject_id=subject,
                )
                rejected = await call("/operations", bearer(grant_b), method="POST", body=conflict)
                assert rejected.status_code == 409 and rejected.json()["error"] == "person_conflict"
                await replay(REPLAYED_FENCED_HISTORY[0], bearer(a), generation=2)
                await replay(REPLAYED_FENCED_HISTORY[1], bearer(b), generation=2)
                other = dict(first, operation_id="13131313-1313-4131-8131-131313131313", subject_id=second_subject)
                assert (await call("/operations", bearer(grant_a), method="POST", body=other)).status_code == 200
                page = await call("/snapshot?limit=100", bearer(a))
                # A genuine server-issued cursor, never the frozen placeholder.
                assert page.status_code == 429, page.text
                assert page.json()["error"] == "rate_limited" and int(page.headers["Retry-After"]) > 0
                cursor = page.json()["retry_cursor"]
                prepared = await call("/removals/prepare", bearer(grant_b), method="POST")
                assert prepared.status_code == 200, prepared.text
                removed = await call(
                    "/removals",
                    bearer(grant_b),
                    method="POST",
                    body={"nonce": prepared.json()["nonce"], "confirm": True, "owner_generation": 2},
                )
                assert removed.status_code == 202 and removed.json()["state"] == "pending"
                uuid.UUID(removed.json()["removal_id"])

                key = Partition(server_id, str(DEFAULT_PROJECT_ID), owner, "synthetic-author")
                sessions = async_sessionmaker(engine, expire_on_commit=False)

                async def finish(action_id):
                    for _ in range(10):
                        async with sessions.begin() as db:
                            result = await erase_batch(db, key, uuid.UUID(action_id))
                        if result["status"] == "completed":
                            return
                    pytest.fail("privacy erasure did not complete")

                await finish(removed.json()["removal_id"])
                await replay(
                    REPLAYED_FENCED_HISTORY[2],
                    bearer(b),
                    generation=3,
                    path="/removals/" + removed.json()["removal_id"],
                )
                await replay(REPLAYED_FENCED_HISTORY[3], bearer(a), generation=3)
                await replay(REPLAYED_FENCED_HISTORY[4], bearer(b), generation=3)
                await replay(REPLAYED_FENCED_HISTORY[5], bearer(a), path="/snapshot?cursor=" + cursor)
                grant_new = await grant(a)
                await replay(REPLAYED_FENCED_HISTORY[6], bearer(grant_new), generation=3, request_generation=2)
                await replay(REPLAYED_FENCED_HISTORY[7], bearer(grant_new), generation=3, request_generation=2)
                withdrawal_id = BY_NAME["withdrawal_completed_no_follows_or_consent"]["body"]["withdrawal_id"]
                withdrawn = await call(
                    "/consent/withdraw",
                    browser(desktop),
                    method="POST",
                    body={"withdrawal_id": withdrawal_id, "owner_generation": 3, "confirm": True},
                )
                assert withdrawn.status_code == 202 and withdrawn.json()["state"] == "pending"
                await replay(REPLAYED_FENCED_HISTORY[8], bearer(grant_new), request_generation=3)
                await finish(withdrawal_id)
                await replay(REPLAYED_FENCED_HISTORY[9], bearer(a), generation=4)
                await replay(REPLAYED_FENCED_HISTORY[10], bearer(b), generation=4)
                await replay(REPLAYED_FENCED_HISTORY[11], browser(desktop), generation=4)
                await replay(REPLAYED_FENCED_HISTORY[12], browser(desktop), request_generation=3)
                await replay(REPLAYED_FENCED_HISTORY[13], browser(desktop), generation=5, request_generation=4)
                await replay(REPLAYED_FENCED_HISTORY[14], bearer(grant_new), request_generation=3)
                await replay(REPLAYED_FENCED_HISTORY[15], bearer(a), generation=5)
                async with engine.connect() as conn:
                    state = (
                        await conn.execute(
                            text(
                                "SELECT owner_generation,consent_state,subject_count,current_revision "
                                "FROM mobile_follow_partitions WHERE owner_id=:owner AND cohort='synthetic-author'"
                            ),
                            {"owner": owner},
                        )
                    ).one()
                    assert state == (5, "available", 0, 0)
                assert tuple(seen) == REPLAYED_FENCED_HISTORY
                print("REAL_HTTP_VECTOR_PASS", ",".join(seen))
        finally:
            if worker.is_alive():
                worker.terminate()
            worker.join(timeout=10)
            if worker.is_alive():
                worker.kill()
                worker.join(timeout=5)
            sock.close()
    finally:
        await engine.dispose()
