# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0

"""Backend-owned negotiation shape tests; NOT a running endpoint or privacy proof."""

import json
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1] / "contracts" / "mobile-activity-v1"


class TraceDraftContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.spec = yaml.safe_load((ROOT / "openapi.yaml").read_text())
        cls.fixtures = json.loads((ROOT / "fixtures.json").read_text())
        cls.responses = json.loads((ROOT / "responses.json").read_text())
        cls.vectors = json.loads((ROOT / "contract-vectors.json").read_text())
        cls.schemas = cls.spec["components"]["schemas"]

    def check_shape(self, schema, value):
        if "$ref" in schema:
            return self.check_shape(self.schemas[schema["$ref"].split("/")[-1]], value)
        for sub in schema.get("allOf", []):
            self.check_shape(sub, value)
        if "oneOf" in schema:
            matches = 0
            for sub in schema["oneOf"]:
                try:
                    self.check_shape(sub, value)
                except AssertionError:
                    continue
                matches += 1
            self.assertEqual(matches, 1, ("oneOf", value))
        if "const" in schema:
            self.assertEqual(value, schema["const"])
        if "enum" in schema:
            self.assertIn(value, schema["enum"])
        typ = schema.get("type")
        if typ and not (value is None and (typ == "null" or (isinstance(typ, list) and "null" in typ))):
            if isinstance(typ, list):
                self.assertTrue(any(self._is_type(value, t) for t in typ))
            else:
                self.assertTrue(self._is_type(value, typ), (typ, value))
        if isinstance(value, dict):
            for key in schema.get("required", []):
                self.assertIn(key, value)
            if schema.get("additionalProperties") is False:
                self.assertFalse(set(value) - set(schema.get("properties", {})))
            for key, sub in schema.get("properties", {}).items():
                if key in value:
                    self.check_shape(sub, value[key])
        elif isinstance(value, list):
            if "maxItems" in schema:
                self.assertLessEqual(len(value), schema["maxItems"])
            for item in value:
                self.check_shape(schema.get("items", {}), item)

    @staticmethod
    def _is_type(value, typ):
        return {
            "object": lambda x: isinstance(x, dict),
            "array": lambda x: isinstance(x, list),
            "integer": lambda x: type(x) is int,
            "string": lambda x: isinstance(x, str),
            "boolean": lambda x: type(x) is bool,
            "null": lambda x: x is None,
        }[typ](value)

    def test_every_local_ref_resolves(self):
        def walk(value):
            if isinstance(value, dict):
                for k, v in value.items():
                    if k == "$ref":
                        self.assertTrue(v.startswith("#/"), v)
                        node = self.spec
                        for segment in v[2:].split("/"):
                            node = node[segment]
                    else:
                        walk(v)
            elif isinstance(value, list):
                for v in value:
                    walk(v)

        walk(self.spec)

    def test_disabled_capability_and_neutral_responses(self):
        self.check_shape(self.schemas["Capabilities"], self.responses["capabilities"])
        self.assertFalse(self.responses["capabilities"]["trace_headlines"])
        self.check_shape(self.schemas["PairedBatch"], self.responses["paired_viewport"])
        self.check_shape(self.schemas["PlatformOverview"], self.responses["platform_suppressed"])
        self.assertEqual(
            self.responses["platform_suppressed"]["active_accounts"],
            self.responses["platform_suppressed"]["prompted_root_sessions"],
        )

    def test_synthetic_future_wire_vectors_are_schema_shaped_not_live(self):
        self.assertTrue(self.vectors["synthetic_draft_only"])
        pairs = {v["id"]: v for v in self.vectors["wire_cases"]}
        self.check_shape(self.schemas["PairedBatch"], pairs["paired-40-calls-overlap-prospective-not-deployed"]["body"])
        self.check_shape(self.schemas["ComponentPage"], pairs["overlapping-breakdown-prospective-not-deployed"]["body"])
        self.check_shape(self.schemas["ComponentDetail"], pairs["detail-after-breakdown"]["body"])
        self.check_shape(self.schemas["Reading"], pairs["partial-zero"]["reading"])
        self.assertEqual(pairs["forbidden-author"]["body"], None)
        self.assertEqual(pairs["partial-zero"]["expected_talkback"], "0 observed traces · Partial coverage")
        pair = pairs["paired-40-calls-overlap-prospective-not-deployed"]["body"]
        page = pairs["overlapping-breakdown-prospective-not-deployed"]["body"]
        detail = pairs["detail-after-breakdown"]["body"]
        self.assertEqual(pair["window"], page["window"])
        self.assertEqual(pair["window"], detail["window"])
        self.assertEqual(pair["items"][0]["author_revision"], page["revision"])
        self.assertEqual(page["revision"], detail["revision"])
        self.assertEqual(pair["items"][0]["author_usage"]["value"], 1)
        self.assertEqual(pair["items"][0]["author_usage"]["status"], "partial")
        self.assertEqual(pair["items"][0]["user_usage"]["status"], "partial")
        self.assertEqual(
            pairs["paired-40-calls-overlap-prospective-not-deployed"]["expected_spoken_author"],
            "1 observed traces · Partial coverage",
        )
        self.assertEqual([i["component_traces"]["value"] for i in page["items"]], [1, 1])
        self.assertEqual(sum(i["mcp_calls"]["value"] for i in page["items"]), 40)

    def test_acceptance_cases_cover_denial_zero_source_replay_and_origin(self):
        ids = {v["id"] for v in self.fixtures["cases"]}
        for expected in (
            "same-id-two-uploaders",
            "parentless-upgraded-child",
            "replay-after-physical-delete",
            "partial-zero",
            "supported-zero",
            "own-author-cross-user",
            "source-timestamp-invalid",
            "scope-repair-during-other-pagination",
            "retention-poison-queue",
        ):
            self.assertIn(expected, ids)
        self.assertNotIn("restricted", self.schemas["ReadingBase"]["properties"]["status"]["enum"])
        self.assertIn("/mobile-activity/v1/people/resolve", self.spec["paths"])
        for route in (
            "/mobile-activity/v1/people/{subject_id}/{scope}/components",
            "/mobile-activity/v1/people/{subject_id}/{scope}/components/{kind}/{component_id}",
        ):
            params = self.spec["paths"][route]["get"]["parameters"]
            self.assertIn("#/components/parameters/ExpectedRevision", [p["$ref"] for p in params if "$ref" in p])

    def test_reject_impossible_status_value_and_projection_pairs(self):
        reading = self.responses["platform_suppressed"]["active_accounts"]
        for status, value, projection in (
            ("supported", None, "complete"),
            ("partial", None, "partial"),
            ("not_recorded", 0, "unavailable"),
            ("supported", 0, "partial"),
            ("restricted", 0, "complete"),
        ):
            forged = {
                **reading,
                "status": status,
                "value": value,
                "coverage": {**reading["coverage"], "projection": projection},
            }
            with self.assertRaises(AssertionError):
                self.check_shape(self.schemas["Reading"], forged)


if __name__ == "__main__":
    unittest.main()
