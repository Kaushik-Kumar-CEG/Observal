# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Old source is a conditional observed MCP preview, never automatic phone backfill."""

import hashlib
import json
import uuid
from datetime import UTC, datetime, timedelta

import pytest

from services.mobile_legacy_attribution import legacy_mcp_candidates, qualify_legacy_mcp

ACTOR = uuid.UUID("11111111-1111-4111-8111-111111111111")
COMPONENT = uuid.UUID("22222222-2222-4222-8222-222222222222")
VERSION = uuid.UUID("33333333-3333-4333-8333-333333333333")
AUTHOR = uuid.UUID("44444444-4444-4444-8444-444444444444")
NOW = datetime.now(UTC).replace(microsecond=0)
WHEN = NOW - timedelta(days=1)


def fixture(calls=1):
    file_hash = "sha256-" + "a" * 64
    layer = hashlib.sha256(json.dumps([["pi/user:mcp.json", file_hash]], sort_keys=True).encode()).hexdigest()[:16]
    snapshot = {
        "project_id": "default",
        "user_id": str(ACTOR),
        "harness": "pi",
        "hash": layer,
        "uploaded_at": (WHEN - timedelta(days=1)).isoformat(),
        "content": json.dumps(
            {
                "harnesses": {"pi": [{"path": "user:mcp.json", "hash": file_hash, "size": 32, "source": "observal"}]},
                "pinned_versions": {
                    "agents": [],
                    "standalone": [
                        {
                            "id": str(COMPONENT),
                            "harness": "pi",
                            "type": "mcp",
                            "local_name": "alpha",
                            "version": "1.2.3",
                        }
                    ],
                },
            }
        ),
    }
    raw = [{"type": "session", "id": "old-root", "timestamp": snapshot["uploaded_at"], "cwd": "/work"}]
    for i in range(calls):
        raw.extend(
            [
                {
                    "type": "message",
                    "timestamp": WHEN.isoformat(),
                    "message": {
                        "role": "assistant",
                        "content": [
                            {
                                "type": "toolCall",
                                "name": "mcp",
                                "id": f"call-{i}",
                                "arguments": {"tool": "read"},
                            }
                        ],
                    },
                },
                {
                    "type": "message",
                    "timestamp": WHEN.isoformat(),
                    "message": {
                        "role": "toolResult",
                        "toolName": "mcp",
                        "toolCallId": f"call-{i}",
                        "isError": False,
                        "details": {"mode": "call", "server": "alpha", "tool": "read"},
                    },
                },
            ]
        )
    rows = [
        {
            "project_id": "default",
            "user_id": str(ACTOR),
            "harness": "pi",
            "session_id": "old-root",
            "line_offset": i,
            "line_hash": hashlib.sha256(json.dumps(record).encode()).hexdigest(),
            "raw_line": json.dumps(record),
            "source_sha256": hashlib.sha256(json.dumps(record).encode()).hexdigest(),
            "raw_line_truncated": False,
            "is_source_record": 1,
            "timestamp": WHEN.isoformat(),
            "layer_hash": layer,
            "parent_session_id": "",
        }
        for i, record in enumerate(raw)
    ]
    return rows, snapshot


def candidates(rows, snapshot, *, modern=False):
    return legacy_mcp_candidates(
        rows, snapshot, project="default", uploader=ACTOR, session="old-root", now=NOW, modern_run_exists=modern
    )


def test_forty_adapter_linked_old_calls_have_one_observed_root_and_unique_pin():
    rows, snapshot = fixture(calls=40)
    calls = candidates(rows, snapshot)
    assert len(calls) == 40
    assert len({(call.uploader, call.root_key) for call in calls}) == 1
    assert all(
        call.result_state == "success" and call.component_id == COMPONENT and call.version == "1.2.3" for call in calls
    )
    assert candidates(rows, snapshot, modern=True) == [], "an admitted modern session owns this root instead"


def test_missing_or_ambiguous_legacy_mapping_parent_ttl_and_wrong_uploader_fail_closed():
    rows, snapshot = fixture()
    assert len(candidates(rows, snapshot)) == 1
    snapshot["uploaded_at"] = (WHEN - timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S.000")
    assert len(candidates(rows, snapshot)) == 1, "ClickHouse UTC DateTime64 omits the timezone in JSON"
    body = json.loads(snapshot["content"])
    body["pinned_versions"]["standalone"] = []
    snapshot["content"] = json.dumps(body)
    assert not candidates(rows, snapshot)
    rows, snapshot = fixture()
    snapshot["user_id"] = str(AUTHOR)
    assert not candidates(rows, snapshot)
    rows, snapshot = fixture()
    snapshot["uploaded_at"] = (NOW + timedelta(minutes=1)).isoformat()
    assert not candidates(rows, snapshot)
    rows, snapshot = fixture()
    rows[0]["parent_session_id"] = "unknown"
    assert not candidates(rows, snapshot)
    rows, snapshot = fixture()
    rows[0]["timestamp"] = (NOW - timedelta(days=31)).isoformat()
    assert not candidates(rows, snapshot)
    rows, snapshot = fixture()
    rows[1]["layer_hash"] = "v2_" + "a" * 64
    assert not candidates(rows, snapshot)
    rows, snapshot = fixture()
    rows[1]["source_sha256"] = ""
    assert not candidates(rows, snapshot), "old rows without an ingestion digest remain unqualified"
    rows, snapshot = fixture()
    rows[-1]["raw_line"] = json.dumps(
        {
            "type": "message",
            "timestamp": WHEN.isoformat(),
            "message": {
                "role": "toolResult",
                "toolCallId": "call-0",
                "isError": False,
                "details": {"mode": "call", "server": "unmapped"},
            },
        }
    )
    rows[-1]["source_sha256"] = hashlib.sha256(rows[-1]["raw_line"].encode()).hexdigest()
    assert not candidates(rows, snapshot), "unmapped result cannot borrow a pin from the tool argument"
    rows, snapshot = fixture()
    body = json.loads(snapshot["content"])
    body["pinned_versions"]["standalone"].append(body["pinned_versions"]["standalone"][0].copy())
    snapshot["content"] = json.dumps(body)
    assert not candidates(rows, snapshot)


@pytest.mark.asyncio
async def test_user_partial_can_remain_when_author_event_time_provenance_is_missing():
    rows, snapshot = fixture()
    calls = candidates(rows, snapshot)

    class Db:
        def __init__(self, author=False, binding=False):
            self.author = author
            self.binding = binding
            self.statements = []

        async def scalar(self, statement, params):
            sql = str(statement)
            self.statements.append(sql)
            if "SELECT v.id" in sql:
                assert "v.released_at<=:when" in sql and params["when"] == WHEN
                return VERSION
            if "FROM mobile_verified_layers" in sql:
                assert params["user"] == ACTOR and params["alias"] == "alpha"
                return 1 if self.binding else None
            if "SELECT p.original_author_id" in sql:
                return AUTHOR if self.author else None
            return 1 if self.author else None

    user_only = await qualify_legacy_mcp(Db(author=False, binding=True), calls)
    assert len(user_only) == 1 and user_only[0].author_id is None
    assert user_only[0].status == "observed_partial"
    unverified = await qualify_legacy_mcp(Db(author=True, binding=False), calls)
    assert unverified == [], "event-time public listing alone cannot prove any person's old alias"
    author = await qualify_legacy_mcp(Db(author=True, binding=True), calls)
    assert len(author) == 1 and author[0].author_id == AUTHOR
