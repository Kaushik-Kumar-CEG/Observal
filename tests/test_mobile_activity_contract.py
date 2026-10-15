# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0

"""Negotiated wire examples must obey paired privacy suppression."""

import copy
import json
from pathlib import Path

import jsonschema
import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1] / "contracts/mobile-activity-v1"
SCHEMA = yaml.safe_load((ROOT / "openapi.yaml").read_text())
EXAMPLES = json.loads((ROOT / "responses.json").read_text())
CASES = json.loads((ROOT / "fixtures.json").read_text())["cases"]


def _validator(schema_name):
    return jsonschema.Draft202012Validator(
        {"components": SCHEMA["components"], "$ref": f"#/components/schemas/{schema_name}"}
    )


def _validate(name, schema_name):
    _validator(schema_name).validate(EXAMPLES[name])


def test_examples_validate_against_the_backend_owned_schema():
    for name, schema in (
        ("mobile_device_challenge", "DeviceChallenge"),
        ("mobile_device_token", "MobileDeviceToken"),
        ("mobile_refresh_token", "MobileTokenPair"),
    ):
        _validate(name, schema)
    for name in ("platform_covered", "platform_suppressed"):
        _validate(name, "PlatformOverview")
    _validate("author_scope_no_general_session_leak", "PersonSummary")
    _validate("people_first_slice", "PeoplePage")
    _validate("published_original_transfer", "PublishedPage")
    _validate("components_unqualified", "ComponentPage")
    _validate("component_observed", "ComponentDetail")
    assert len(CASES) >= 5


@pytest.mark.parametrize("field", ["active_accounts", "prompted_root_sessions"])
@pytest.mark.parametrize(
    ("path", "leak"),
    [
        (("coverage", "eligible_sessions"), 3),
        (("coverage", "source_start"), "2026-09-23T00:00:00Z"),
        (("coverage", "supported_harnesses"), ["pi"]),
        (("coverage", "projection"), "partial"),
        (("reasons",), ["small_cohort"]),
        (("value",), 3),
    ],
)
def test_suppressed_platform_cannot_disclose_count_or_coverage(field, path, leak):
    reading = EXAMPLES["platform_suppressed"][field]
    assert reading["reasons"] == ["unavailable"]
    assert reading["coverage"] == {
        "eligible_sessions": None,
        "source_start": None,
        "source_end": None,
        "supported_harnesses": [],
        "projection": "unavailable",
    }
    broken = copy.deepcopy(EXAMPLES["platform_suppressed"])
    cursor = broken[field]
    for key in path[:-1]:
        cursor = cursor[key]
    cursor[path[-1]] = leak
    with pytest.raises(jsonschema.ValidationError):
        _validator("PlatformOverview").validate(broken)


@pytest.mark.parametrize("leak", ["source_start", "source_end", "eligible_sessions", "supported_harnesses"])
def test_author_general_sessions_cannot_disclose_another_person_coverage(leak):
    broken = copy.deepcopy(EXAMPLES["author_scope_no_general_session_leak"])
    broken["general_sessions"]["coverage"][leak] = ["pi"] if leak == "supported_harnesses" else 1
    with pytest.raises(jsonschema.ValidationError):
        _validator("PersonSummary").validate(broken)


def test_platform_must_suppress_both_readings_together():
    broken = copy.deepcopy(EXAMPLES["platform_suppressed"])
    broken["active_accounts"] = EXAMPLES["platform_covered"]["active_accounts"]
    with pytest.raises(jsonschema.ValidationError):
        _validator("PlatformOverview").validate(broken)
