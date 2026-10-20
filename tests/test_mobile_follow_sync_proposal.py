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
SPEC = yaml.safe_load((ROOT / "follow-sync-v1-openapi.yaml").read_text())
VECTORS = json.loads((ROOT / "follow-sync-v1-vectors.json").read_text())
SPEC_URI = "https://observal.example.test/mobile-follow-sync/1.0.1"
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


def test_follow_sync_proposal_pins_exact_schema_and_vector_files():
    import hashlib

    proposal = (ROOT / "FOLLOW_SYNC_V1_PROPOSAL.md").read_text()
    for name in ("follow-sync-v1-openapi.yaml", "follow-sync-v1-vectors.json"):
        assert hashlib.sha256((ROOT / name).read_bytes()).hexdigest() in proposal


def test_separate_sync_scopes_never_write_with_v12_read_token():
    assert SPEC["info"]["version"] == "1.0.1-proposal"
    paths = SPEC["paths"]
    writes = {
        "/mobile-follow-sync/v1/operations",
        "/mobile-follow-sync/v1/removals/prepare",
        "/mobile-follow-sync/v1/removals",
    }
    for path, operations in paths.items():
        for method, operation in operations.items():
            assert "429" in operation["responses"], (path, method)
            if method == "post":
                assert "413" in operation["responses"], (path, method)
            if method == "post" and path in writes:
                assert operation["security"] == [{"followWrite": []}]
            elif path == "/mobile-follow-sync/v1/write-approval":
                assert operation["security"] == [{"browserBearer": []}]
            else:
                assert operation["security"] == [{"mobileRead": []}]
    assert not any(path.startswith("/mobile-activity/v1") for path in paths)
    assert all(path.startswith("/mobile-follow-sync/v1/") for path in paths)
    assert len(VECTORS["cases"]) >= 25


def _path_template(path: str) -> str:
    path = urlparse(path).path
    if re.fullmatch(r"/mobile-follow-sync/v1/operations/[a-f0-9-]{36}", path):
        return "/mobile-follow-sync/v1/operations/{operation_id}"
    if re.fullmatch(r"/mobile-follow-sync/v1/removals/[a-f0-9-]{36}", path):
        return "/mobile-follow-sync/v1/removals/{removal_id}"
    return path


@pytest.mark.parametrize("case", VECTORS["cases"], ids=lambda case: case["name"])
def test_proposal_vectors_match_strict_request_and_response_schemas(case):
    if case["method"] == "none" or case["name"] == "older_server_after_fresh_v12_proof":
        # This is the required absence-of-extension fallback, not an actual
        # new-server response or a fabricated server-synced empty list.
        assert "local_follows_only" in case.get("client_result", "") or case["method"] == "none"
        return
    if case["name"] == "write_token_cannot_read_activity_or_admin":
        assert _path_template(case["path"]) not in SPEC["paths"]
        assert case["status"] == 401  # Existing v1.2 audience remains exact mobile:read.
        return
    route = SPEC["paths"][_path_template(case["path"])][case["method"].lower()]
    response = route["responses"][str(case["status"])]
    if "$ref" in response:
        response = SPEC["components"]["responses"][response["$ref"].split("/")[-1]]
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
            jsonschema.Draft202012Validator(
                schema, registry=REGISTRY, format_checker=jsonschema.FormatChecker()
            ).validate(body)
