# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Synthetic trace-first wire must reject impossible and privacy-leaking readings."""

import copy
import json
from pathlib import Path

import jsonschema
import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1] / "contracts/mobile-activity-v1"
SCHEMA = yaml.safe_load((ROOT / "openapi.yaml").read_text())
EXAMPLES = json.loads((ROOT / "responses.json").read_text())
VECTORS = json.loads((ROOT / "contract-vectors.json").read_text())


def validator(schema):
    return jsonschema.Draft202012Validator(
        {"components": SCHEMA["components"], "$ref": f"#/components/schemas/{schema}"}
    )


def test_disabled_capability_and_paired_synthetic_wire_validate():
    for name, kind in (
        ("capabilities", "Capabilities"),
        ("paired_viewport", "PairedBatch"),
        ("platform_suppressed", "PlatformOverview"),
    ):
        validator(kind).validate(EXAMPLES[name])
    assert EXAMPLES["capabilities"]["trace_headlines"] is False
    pair = EXAMPLES["paired_viewport"]
    assert all(
        item["author_usage"]["status"] == "not_recorded" or item["author_usage"]["status"] == "partial"
        for item in pair["items"]
    )


@pytest.mark.parametrize("field", ["active_accounts", "prompted_root_sessions"])
@pytest.mark.parametrize(
    ("path", "leak"),
    [
        (("coverage", "eligible_sessions"), 3),
        (("coverage", "source_start"), "2026-09-23T00:00:00Z"),
        (("coverage", "supported_harnesses"), ["pi"]),
        (("coverage", "supported_kinds"), ["mcp_calls"]),
        (("coverage", "projection"), "partial"),
        (("reasons",), ["small_cohort"]),
        (("value",), 3),
    ],
)
def test_suppressed_platform_pair_cannot_expose_count_or_metadata(field, path, leak):
    broken = copy.deepcopy(EXAMPLES["platform_suppressed"])
    cursor = broken[field]
    for key in path[:-1]:
        cursor = cursor[key]
    cursor[path[-1]] = leak
    with pytest.raises(jsonschema.ValidationError):
        validator("PlatformOverview").validate(broken)


def test_platform_values_suppress_together():
    broken = copy.deepcopy(EXAMPLES["platform_suppressed"])
    paired = next(v for v in VECTORS["wire_cases"] if v["id"].startswith("paired-40"))
    broken["active_accounts"] = paired["body"]["items"][0]["author_usage"]
    with pytest.raises(jsonschema.ValidationError):
        validator("PlatformOverview").validate(broken)


@pytest.mark.parametrize(
    ("path", "leak"),
    [
        (("author_usage", "value"), 0),
        (("author_usage", "coverage"), {"projection": "partial"}),
        (("author_usage", "reasons"), ["small_cohort"]),
        (("author_revision",), "private-epoch-hash"),
        (("user_revision",), "private-epoch-hash"),
    ],
)
def test_mixed_batch_restricted_scope_cannot_expose_metadata(path, leak):
    vector = next(v for v in VECTORS["wire_cases"] if v["id"].startswith("mixed-twelve-"))
    broken = copy.deepcopy(vector["body"])
    row = broken["items"][0]
    target = row
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = leak
    with pytest.raises(jsonschema.ValidationError):
        validator("PairedBatch").validate(broken)


def test_wire_supports_independently_allowed_author_with_forbidden_user():
    mixed = next(v for v in VECTORS["wire_cases"] if v["id"].startswith("mixed-twelve-"))
    paired = next(v for v in VECTORS["wire_cases"] if v["id"].startswith("paired-40"))
    future_policy = copy.deepcopy(mixed["body"])
    future_policy["items"][0]["author_revision"] = "A1"
    future_policy["items"][0]["author_usage"] = paired["body"]["items"][0]["author_usage"]
    validator("PairedBatch").validate(future_policy)
    assert future_policy["items"][0]["user_usage"] == {"status": "restricted"}


def test_restricted_reading_is_never_a_body_value():
    sample = copy.deepcopy(EXAMPLES["platform_suppressed"]["active_accounts"])
    sample["status"] = "restricted"
    sample["value"] = 0
    with pytest.raises(jsonschema.ValidationError):
        validator("Reading").validate(sample)
