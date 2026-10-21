# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Negotiation-only strict sync proposal; NOT server implementation or Android ACK."""

import json
import re
from pathlib import Path
from urllib.parse import urlparse

import jsonschema
import pytest
import yaml
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

ROOT = Path(__file__).resolve().parents[1] / "contracts/mobile-activity-v1"
SPEC = yaml.safe_load((ROOT / "follow-sync-v104-draft-openapi.yaml").read_text())
VECTORS = json.loads((ROOT / "follow-sync-v104-draft-vectors.json").read_text())
SPEC_URI = "https://observal.example.test/mobile-follow-sync/1.0.4"
REGISTRY = Registry().with_resource(SPEC_URI, Resource(contents=SPEC, specification=DRAFT202012))


def test_follow_sync_proposal_does_not_mutate_accepted_v12_bytes():
    import hashlib

    expected = {
        "openapi.yaml": "1e4a475218c6e1ca57310c10a8d73e79c89ef3bda48ce8c1fa2050f9397673f2",
        "fixtures.json": "ea5889fd8a889b1afde30fecd8570b431cf6773ca3e4f3db0f0c55df892f907a",
        "responses.json": "c456e2d39c2210e7e30a0c96be2448adced0540afdfe8a6fd8930ed239d32614",
        "contract-vectors.json": "243636e425aa1414ee3d116af9f6d4281a03e3c1a6cfceed516bbaafbf453462",
    }
    for file, sha in expected.items():
        assert hashlib.sha256((ROOT / file).read_bytes()).hexdigest() == sha


def test_follow_sync_draft_is_not_an_immutable_hash_packet():
    proposal = (ROOT / "FOLLOW_SYNC_V104_DRAFT.md").read_text()
    handoff = (ROOT / "FOLLOW_SYNC_104_SHARED_DRAFT_HANDOFF.md").read_text()
    assert "MUTABLE SHARED DRAFT" in proposal and "BEFORE any three-hash packet" in handoff
    for name in ("follow-sync-v104-draft-openapi.yaml", "follow-sync-v104-draft-vectors.json"):
        assert name in proposal and name in handoff


def test_separate_sync_scopes_never_write_with_v12_read_token():
    assert SPEC["info"]["version"] == VECTORS["version"] == "1.0.4-draft"
    paths = SPEC["paths"]
    writes = {
        "/mobile-follow-sync/v1/operations",
        "/mobile-follow-sync/v1/removals/prepare",
        "/mobile-follow-sync/v1/removals",
        "/mobile-follow-sync/v1/consent/withdraw",
    }
    for path, operations in paths.items():
        for method, operation in operations.items():
            assert "429" in operation["responses"], (path, method)
            if method == "post":
                assert "413" in operation["responses"], (path, method)
            if path in {
                "/mobile-follow-sync/v1/consent/withdraw",
                "/mobile-follow-sync/v1/consent/withdrawals/{withdrawal_id}",
            }:
                expected = (
                    [{"followWrite": []}, {"browserBearer": []}]
                    if method == "post"
                    else [{"mobileRead": []}, {"browserBearer": []}]
                )
                assert operation["security"] == expected
            elif method == "post" and path in writes:
                assert operation["security"] == [{"followWrite": []}]
            elif path in {
                "/mobile-follow-sync/v1/write-approval",
                "/mobile-follow-sync/v1/consent",
                "/mobile-follow-sync/v1/consent/state",
            }:
                assert operation["security"] == [{"browserBearer": []}]
            else:
                assert operation["security"] == [{"mobileRead": []}]
    assert not any(path.startswith("/mobile-activity/v1") for path in paths)
    assert all(path.startswith("/mobile-follow-sync/v1/") for path in paths)
    assert len(VECTORS["cases"]) >= 80


def test_generation_consent_old_server_and_lossless_js_regressions():
    by_name = {case["name"]: case for case in VECTORS["cases"]}
    assert len(by_name) == len(VECTORS["cases"])
    queued = by_name["phone_a_queues_unseen_base0_at_generation_7"]
    removed = by_name["phone_b_remove_all_atomically_advances_to_8"]
    late = by_name["phone_a_late_unseen_base0_replay_cannot_resurrect"]
    assert queued["request"]["base_person_revision"] == 0
    assert queued["request"]["subject_id"] == late["request"]["subject_id"]
    assert queued["request"]["owner_generation"] == 7
    assert removed["body"]["owner_generation"] == late["body"]["owner_generation"] == 8
    assert late["status"] == 409 and late["body"]["error"] == "generation_conflict"
    stale_ack = by_name["phone_a_alternate_history_lost_200_from_pre_removal_status_redacted"]
    assert stale_ack["body"]["effective"] is False
    assert stale_ack["body"]["result"]["status"] == "superseded"
    assert "subject_id" not in stale_ack["body"]["result"]
    withdrawn = by_name["phone_a_requests_explicit_consent_withdrawal"]
    pending = by_name["phone_b_offline_pending_edit_after_withdrawal_revoked"]
    reconsent = by_name["phone_b_fresh_reconsent_advances_to_10"]
    assert (withdrawn["request"]["owner_generation"], withdrawn["body"]["owner_generation"]) == (8, 9)
    assert pending["request"]["owner_generation"] == 8 and pending["status"] == 401
    assert by_name["phone_b_valid_gen10_grant_stale_gen8_intent_conflicts"]["body"]["owner_generation"] == 10
    assert by_name["phone_b_stale_prewithdrawal_opt_in_after_phone_a_completion"]["status"] == 409
    assert by_name["phone_b_approval_code_from_old_generation_revoked"]["status"] == 409
    assert by_name["phone_b_lost_202_old_write_grant_cannot_replay"]["status"] == 401
    assert by_name["phone_b_lost_202_read_authenticated_nonce_lookup"]["body"]["owner_generation"] == 8
    assert by_name["subject_erasure_redacts_same_generation_operation_status"]["body"]["effective"] is False
    assert reconsent["body"]["owner_generation"] == 10
    availability = SPEC["paths"]["/mobile-follow-sync/v1/availability"]["get"]["responses"]
    assert "404" in availability and "405" in availability
    assert not availability["404"].get("content") and not availability["405"].get("content")
    safe = 9_007_199_254_740_991
    for name in ("UnsignedSafeInt", "PositiveSafeInt"):
        assert SPEC["components"]["schemas"][name]["maximum"] == safe
    assert by_name["max_safe_json_revision_accepted"]["request"]["base_person_revision"] == safe - 1
    assert by_name["max_safe_json_revision_accepted"]["body"]["person_revision"] == safe
    assert by_name["phone_b_exact_max_safe_change_ordinal"]["body"]["changes"][0]["change_ordinal"] == safe
    assert (
        by_name["over_js_safe_base_revision_rejected_before_number_rounding"]["request"]["base_person_revision"]
        == safe + 1
    )
    assert by_name["over_js_safe_after_revision_query_rejected"]["status"] == 400
    assert SPEC["components"]["schemas"]["Availability"]["properties"]["project_id"]["maxLength"] == 256
    assert SPEC["components"]["schemas"]["Error"]["properties"]["error"]["maxLength"] == 64
    assert SPEC["components"]["parameters"]["Cursor"]["schema"]["maxLength"] == 1300
    origin = "https://" + "a" * 504  # 512-character canonical origin, inclusive.
    longest = (
        f"{origin}/api/v1/mobile-follow-sync/v1/changes?owner_generation={safe}&after_revision={safe}&limit=100&cursor="
        + "c" * 1300
    )
    assert len(origin) == 512 and len(longest) <= 2048
    assert by_name["phone_b_mobile_read_cannot_restore_opt_in_after_withdrawal"]["status"] == 401
    assert by_name["phone_a_already_available_new_consent_id_cannot_invalidate_follows"]["status"] == 409
    assert (
        by_name["phone_a_same_generation_subject_erasure_denies_original_post_replay"]["body"]["error"]
        == "subject_erased"
    )
    assert by_name["phone_b_browser_withdraws_after_last_phone_unlinked"]["status"] == 202
    assert by_name["phone_b_browser_checks_erasure_after_last_phone_lost"]["body"]["state"] == "completed"
    assert by_name["lost_200_lookup_effective_applied_exact"]["body"]["result"]["status"] == "applied"
    assert by_name["lost_409_lookup_effective_conflict_exact"]["body"]["result"]["error"] == "person_conflict"
    for name in (
        "lost_200_contradictory_applied_with_original_409_rejected",
        "lost_409_contradictory_conflict_with_original_200_rejected",
        "lost_200_after_erasure_false_with_applied_payload_rejected",
    ):
        assert by_name[name]["invalid_response_schema"] is True


def test_bounded_owner_wide_lease_reuse_and_historical_ack_draft():
    """Illustrative contract bounds, NOT real-store acceptance or Android feedback."""
    by = {case["name"]: case for case in VECTORS["cases"]}
    snap = by["capacity_snapshot_page_1_not_authoritative"]
    export = by["capacity_export_page_1_is_not_full_export"]
    change = by["capacity_changes_first_page_pins_fixed_upper"]
    for case in (snap, export, change):
        assert case.get("capacity", case.get("eligible_changes")) == 1000
        assert case["expected_pages"] == 10 and case["page_size"] == 100
        assert (
            case["body"]["complete"] is False and len(case["body"].get("items", case["body"].get("changes", []))) == 100
        )
        assert case["lease_expires_after_admission_seconds"] == 900
    assert snap["body"]["read_lease_id"] == export["body"]["read_lease_id"]
    assert (
        by["owner_initial_429_lost_retries_cursorless_without_new_pinned_image"]["body"]["read_lease_id"]
        == snap["body"]["read_lease_id"]
    )
    assert (
        by["owner_initial_429_lost_retries_cursorless_without_new_pinned_image"]["cursorless_admissions_attempted"]
        == 10000
    )
    assert by["phone_b_concurrent_export_reuses_phone_a_image"]["owner_pinned_images"] == 1
    assert by["non_equivalent_phone_b_changes_use_shared_snapshot_fallback"]["body"]["error"] == "snapshot_required"
    assert by["fresh_lease_budget_exhausted_before_first_429"]["status"] == 503
    assert by["owner_budget_released_at_15min_next_first_request_recovers"]["status"] == 200
    assert by["capacity_snapshot_page_10_after_one_retry"]["elapsed_seconds"] == 10 * (60 + 5) < 900
    assert by["capacity_changes_page_10_fixed_upper_after_restart_and_new_writes"]["body"]["revision"] == 1000
    assert by["over_1000_change_window_falls_back_before_first_page"]["eligible_changes"] == 1001
    assert by["capacity_changes_first_page_pins_fixed_upper"]["oldest_delta_age_days_at_admission"] == 89
    assert by["delta_older_than_89_days_falls_back_before_admission"]["status"] == 409
    assert by["availability_current_revision_after_phone_b_unfollow"]["body"]["current_revision"] == 2
    assert by["stale_shared_image_rev1_rejected_for_phone_b_min_rev2"]["status"] == 503
    fresh = by["stale_lease_expired_new_image_proves_rev2_unfollow"]
    assert fresh["status"] == 200 and fresh["body"]["revision"] == 2 and fresh["body"]["complete"] is True
    assert by["history_a_lost_200_lookup_historical_not_synced"]["body"]["effective"] is True
    assert "NOT_following" in by["history_a_complete_delta_reconciles_after_lost_200"]["client_result"]
    assert by["history_a_full_snapshot_rev2_confirms_not_following"]["body"]["complete"] is True
    for error in ("subject_erased", "generation_conflict"):
        assert by[f"{error}_409_redacted_no_person_fields"]["body"]["error"] == error
        for key in ("revision", "person_revision", "current_following"):
            assert by[f"{error}_409_reject_unexpected_{key}"]["invalid_response_schema"] is True


def test_yaml_parsed_shape_has_no_phantom_null_description_keys():
    def visit(value):
        if isinstance(value, dict):
            for key, child in value.items():
                assert key is not None and child is not None, key
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    visit(SPEC)
    assert set(SPEC["components"]["parameters"]["PageLimit"]) == {"name", "in", "required", "schema", "description"}
    assert set(SPEC["components"]["parameters"]["Cursor"]) == {"name", "in", "required", "schema", "description"}
    for name in ("SnapshotPage", "ChangesPage"):
        assert set(SPEC["components"]["schemas"][name]["properties"]["read_lease_id"]) == {
            "type",
            "format",
            "description",
        }
    for item in SPEC["components"]["securitySchemes"].values():
        assert set(item) == {"type", "scheme", "bearerFormat", "description"}
    for item in SPEC["components"]["responses"].values():
        assert set(item) <= {"description", "content", "headers"}
        assert isinstance(item["description"], str)
    unavailable = SPEC["components"]["responses"]["Unavailable"]
    assert unavailable["headers"]["Retry-After"]["required"] is True
    assert unavailable["headers"]["Retry-After"]["schema"] == {"type": "integer", "minimum": 1, "maximum": 60}
    for path, methods in SPEC["paths"].items():
        for method, operation in methods.items():
            assert set(operation) <= {
                "operationId",
                "security",
                "description",
                "responses",
                "parameters",
                "requestBody",
            }, (path, method)
            for response in operation["responses"].values():
                assert set(response) <= {"description", "content", "headers", "$ref"}


def _android_accepts_outcome(body: dict, requested_operation_id: str) -> bool:
    """Strict proposed client rule beyond JSON Schema's cross-field equality support."""
    schema = {"$ref": SPEC_URI + "#/components/schemas/OperationOutcome"}
    validator = jsonschema.Draft202012Validator(schema, registry=REGISTRY, format_checker=jsonschema.FormatChecker())
    if not validator.is_valid(body):
        return False
    result = body["result"]
    if body["operation_id"] != requested_operation_id or result["owner_generation"] != body["owner_generation"]:
        return False
    if body["effective"]:
        return result["operation_id"] == requested_operation_id and (
            (body["original_http_status"] == 200 and result.get("status") == "applied")
            or (body["original_http_status"] == 409 and "error" in result)
        )
    before = result["original_owner_generation"]
    return (result["reason"] == "owner_reset" and before < body["owner_generation"]) or (
        result["reason"] == "subject_erased" and before == body["owner_generation"]
    )


def test_original_status_and_outcome_are_inseparable_in_schema_and_strict_client():
    by_name = {case["name"]: case for case in VECTORS["cases"]}
    for name in (
        "lost_200_lookup_effective_applied_exact",
        "lost_409_lookup_effective_conflict_exact",
        "lost_409_after_owner_reset_redacted",
        "subject_erasure_redacts_same_generation_operation_status",
    ):
        case = by_name[name]
        assert _android_accepts_outcome(case["body"], case["path"].rsplit("/", 1)[-1]), name
    for name in (
        "lost_200_contradictory_applied_with_original_409_rejected",
        "lost_409_contradictory_conflict_with_original_200_rejected",
        "lost_200_after_erasure_false_with_applied_payload_rejected",
        "lost_409_effective_wrong_generation_rejected",
        "lost_200_lookup_effective_applied_wrong_path_id_rejected",
        "lost_409_lookup_effective_conflict_wrong_path_id_rejected",
    ):
        case = by_name[name]
        assert not _android_accepts_outcome(case["body"], case["path"].rsplit("/", 1)[-1]), name


def _path_template(path: str) -> str:
    path = urlparse(path).path
    if re.fullmatch(r"/mobile-follow-sync/v1/operations/[a-f0-9-]{36}", path):
        return "/mobile-follow-sync/v1/operations/{operation_id}"
    if re.fullmatch(r"/mobile-follow-sync/v1/removals/[a-f0-9-]{36}", path):
        return "/mobile-follow-sync/v1/removals/{removal_id}"
    if re.fullmatch(r"/mobile-follow-sync/v1/consent/withdrawals/[a-f0-9-]{36}", path):
        return "/mobile-follow-sync/v1/consent/withdrawals/{withdrawal_id}"
    return path


@pytest.mark.parametrize("case", VECTORS["cases"], ids=lambda case: case["name"])
def test_proposal_vectors_match_strict_request_and_response_schemas(case):
    if case["method"] == "none" or case["status"] == 0:
        assert case["method"] == "none" or "NOT_SENT" in case["client_result"]
        return
    if case.get("invalid_server_sequence"):
        assert case["name"] == "capacity_same_page_second_429_is_contract_violation"
        assert "violates_progress_guarantee" in case["client_result"]
    if case.get("invalid_client_cross_field"):
        assert not _android_accepts_outcome(case["body"], case["path"].rsplit("/", 1)[-1]), case["name"]
    if case["name"] == "write_grant_cannot_use_v12_activity":
        assert _path_template(case["path"]) not in SPEC["paths"]
        assert case["status"] == 401  # Existing v1.2 audience remains exact mobile:read.
        return
    route = SPEC["paths"][_path_template(case["path"])][case["method"].lower()]
    if case["status"] == 302:
        assert "302" not in route["responses"] and "lock" in case["client_result"]
        return
    response = route["responses"][str(case["status"])]
    if case["method"] == "GET" and any(
        case["path"].startswith(f"/mobile-follow-sync/v1/{p}") for p in ("snapshot", "export", "changes")
    ):
        from urllib.parse import parse_qs

        supplied_limit = parse_qs(urlparse(case["path"]).query).get("limit", ["100"])[0]
        if supplied_limit != "100":
            assert case["status"] == 400, case["name"]
    if "raw_body" in case:
        assert case["status"] in (404, 405) and not response.get("content")
        assert ("local_follows_only" in case["client_result"]) == case["credential"].startswith("fresh_v12_")
        return
    if "$ref" in response:
        response = SPEC["components"]["responses"][response["$ref"].split("/")[-1]]
    if case["status"] == 503:
        assert response["headers"]["Retry-After"]["required"] is True
        assert 1 <= int(case["headers"]["Retry-After"]) <= 60
    for body, schema in (
        (
            case.get("request"),
            route.get("requestBody", {}).get("content", {}).get("application/json", {}).get("schema"),
        ),
        (case.get("body"), response.get("content", {}).get("application/json", {}).get("schema")),
    ):
        if body is not None:
            assert schema is not None, case["name"]
            if "$ref" in schema:
                schema = {"$ref": SPEC_URI + schema["$ref"]}
            validator = jsonschema.Draft202012Validator(
                schema, registry=REGISTRY, format_checker=jsonschema.FormatChecker()
            )
            intentionally_invalid = (
                case["name"] == "unknown_200_version_not_fallback" and body is case.get("body")
            ) or (
                case["name"] == "over_js_safe_base_revision_rejected_before_number_rounding"
                and body is case.get("request")
            )
            intentionally_invalid = intentionally_invalid or (
                case.get("invalid_response_schema", False) and body is case.get("body")
            )
            assert validator.is_valid(body) is not intentionally_invalid, case["name"]
