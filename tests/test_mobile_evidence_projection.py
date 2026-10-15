# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Never turn unverified or malformed client evidence into a measured zero."""

import json
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from jobs.mobile_evidence import _matched, _qualified_lineage, _revision, _zero_activities
from services.session_parsers.pi_invocations import PiInvocationExtractor

_COMPONENT = uuid.uuid4()
_HASH = "v2_" + "a" * 64


def _row(offset, message, *, layer_hash=_HASH, parent=None, timestamp=None, event_type="tool_call"):
    raw = json.dumps({"type": "message", "timestamp": timestamp or "2026-10-01T12:00:00Z", "message": message})
    return {
        "is_source_record": 1,
        "project_id": "default",
        "user_id": str(uuid.uuid4()),
        "harness": "pi",
        "session_id": "session-1",
        "line_offset": offset,
        "line_hash": "0" * 64 if offset == 0 else str(offset),
        "raw_line": raw,
        "layer_hash": layer_hash,
        "event_type": event_type,
        "parent_session_id": parent,
        "raw_line_truncated": 0,
    }


def _call(call_id):
    return {"type": "toolCall", "id": call_id, "name": "mcp", "arguments": {"server": "alpha", "tool": "fetch"}}


def _result(call_id):
    return {
        "role": "toolResult",
        "toolCallId": call_id,
        "toolName": "mcp",
        "isError": False,
        "details": {"mode": "call", "server": "alpha", "tool": "fetch"},
        "content": [],
    }


def test_zero_cohort_requires_valid_tool_free_activity_and_v2_mapping():
    from datetime import UTC, datetime

    now = datetime.now(UTC).isoformat()
    line = {"type": "message", "timestamp": now, "message": {"role": "user", "content": "go"}}
    row = {"raw_line": json.dumps(line), "line_offset": 1, "layer_hash": "v2_" + "a" * 64, "event_type": "user_prompt"}
    assert _zero_activities([row]) == [(1, datetime.fromisoformat(now), row["layer_hash"])]
    assert _zero_activities([{**row, "layer_hash": "legacy"}]) is None
    assert _zero_activities([{**row, "raw_line": json.dumps({**line, "timestamp": None})}]) is None
    assert (
        _zero_activities(
            [
                {
                    **row,
                    "raw_line": json.dumps(
                        {**line, "message": {"role": "assistant", "content": [{"type": "toolCall", "name": "mcp"}]}}
                    ),
                }
            ]
        )
        is None
    )
    assert (
        _zero_activities(
            [{**row, "raw_line": json.dumps({**line, "message": {"role": "toolResult", "toolName": "mcp"}})}]
        )
        is None
    )


def test_forty_independently_linked_calls_one_logical_root():
    # One assistant line can contain multiple calls. A summary-row tool count
    # would undercount these 40 events as only one.
    rows = [_row(0, {"role": "user", "content": "real prompt"}, event_type="user_prompt")]
    rows += [_row(1, {"role": "assistant", "content": [_call(f"c{i}") for i in range(40)]})]
    rows += [_row(i + 2, _result(f"c{i}")) for i in range(40)]
    extracted = PiInvocationExtractor().extract(rows)
    verified = uuid.uuid4()
    facts, partial = _matched(extracted, rows, {_HASH: {"alpha": _COMPONENT}}, verified_root=verified)
    assert len(facts) == 40 and not partial
    assert {r["root_run_incarnation"] for r in facts} == {verified}
    assert len({(r["source_line_offset"], r["block_key"]) for r in facts}) == 40
    assert {r["root_session_id"] for r in facts} == {"session-1"}
    assert len({r["event_time"].date() for r in facts}) == 1
    assert _revision(rows) == _revision(list(rows)), "identical retries keep one revision"


@pytest.mark.asyncio
async def test_child_chain_only_resolves_causal_scoped_qualified_root():
    start = datetime.now(UTC)
    root = uuid.uuid4()
    scope = {"project": "default", "user": uuid.uuid4(), "harness": "pi", "session": "child"}
    parent = SimpleNamespace(
        session_id="parent",
        run_incarnation=root,
        header_hash="a" * 64,
        started_at=start,
        parent_session_id=None,
        parent_run_incarnation=None,
        parent_header_hash=None,
        origin_witness="pi_session_start_root_v1",
        root_verified=True,
        source_status="complete",
    )

    class Db:
        async def execute(self, _sql, params):
            assert params["parent"] == "parent" and params["user"] == scope["user"]
            return SimpleNamespace(first=lambda: parent)

    run = SimpleNamespace(parent_session_id="parent", parent_run_incarnation=root, parent_header_hash="a" * 64)
    assert await _qualified_lineage(Db(), scope, run, start + timedelta(seconds=1)) == ("parent", root, start)
    parent.started_at = start + timedelta(seconds=2)
    assert await _qualified_lineage(Db(), scope, run, start + timedelta(seconds=1)) is None
    parent.started_at = start
    parent.root_verified = False
    assert await _qualified_lineage(Db(), scope, run, start + timedelta(seconds=1)) is None


def test_unprompted_calls_have_no_qualified_root_or_trace():
    rows = [_row(0, {"role": "assistant", "content": [_call("id")]}), _row(1, _result("id"))]
    facts, partial = _matched(PiInvocationExtractor().extract(rows), rows, {_HASH: {"alpha": _COMPONENT}})
    assert len(facts) == 1 and facts[0]["root_session_id"] is None and partial
    verified = uuid.uuid4()
    attributed, partial = _matched(
        PiInvocationExtractor().extract(rows), rows, {_HASH: {"alpha": _COMPONENT}}, verified_root=verified
    )
    assert len(attributed) == 1 and attributed[0]["root_run_incarnation"] == verified and not partial


def test_missing_source_time_cannot_inherit_clickhouse_time():
    rows = [_row(0, {"role": "assistant", "content": [_call("id")]}), _row(1, _result("id"))]
    rows[0]["raw_line"] = json.dumps({"type": "message", "message": {"role": "assistant", "content": [_call("id")]}})
    rows[0]["timestamp"] = "2026-10-01T12:00:00Z"
    facts, partial = _matched(PiInvocationExtractor().extract(rows), rows, {_HASH: {"alpha": _COMPONENT}})
    assert not facts and partial


def test_unmatched_and_legacy_layers_never_create_attributed_events():
    rows = [_row(0, {"role": "assistant", "content": [_call("id")]}), _row(1, _result("id"))]
    extracted = PiInvocationExtractor().extract(rows)
    assert _matched(extracted, rows, {_HASH: {"other": _COMPONENT}}) == ([], True)
    rows[0]["layer_hash"] = "legacy-hash"
    assert _matched(extracted, rows, {_HASH: {"alpha": _COMPONENT}}) == ([], True)


def test_child_call_keeps_event_but_does_not_guess_parent_root():
    rows = [
        _row(0, {"role": "assistant", "content": [_call("child")]}, parent="parent"),
        _row(1, _result("child"), parent="parent"),
    ]
    facts, partial = _matched(PiInvocationExtractor().extract(rows), rows, {_HASH: {"alpha": _COMPONENT}})
    assert len(facts) == 1 and facts[0]["root_session_id"] is None and partial


def test_child_requires_bound_parent_root_and_events_cannot_predate_child_start():
    root = uuid.uuid4()
    rows = [
        _row(0, {"role": "assistant", "content": [_call("child")]}, parent="parent"),
        _row(1, _result("child"), parent="parent"),
    ]
    extracted = PiInvocationExtractor().extract(rows)
    blocked, partial = _matched(extracted, rows, {_HASH: {"alpha": _COMPONENT}}, verified_root=root)
    assert len(blocked) == 1 and blocked[0]["root_run_incarnation"] is None and partial
    facts, partial = _matched(
        extracted,
        rows,
        {_HASH: {"alpha": _COMPONENT}},
        verified_root=root,
        allow_child=True,
        root_session_id="parent",
        root_start=datetime(2026, 10, 1, 11, 59, tzinfo=UTC),
    )
    assert len(facts) == 1 and not partial
    assert facts[0]["root_session_id"] == "parent" and facts[0]["root_run_incarnation"] == root
    forged, partial = _matched(
        extracted,
        rows,
        {_HASH: {"alpha": _COMPONENT}},
        verified_root=root,
        allow_child=True,
        root_start=datetime(2026, 10, 1, 12, 1, tzinfo=UTC),
    )
    assert not forged and partial


def test_unknown_time_is_not_defaulted_into_selected_window():
    rows = [
        _row(0, {"role": "assistant", "content": [_call("id")]}, timestamp="bad-time"),
        _row(1, _result("id"), timestamp="bad-time"),
    ]
    facts, partial = _matched(PiInvocationExtractor().extract(rows), rows, {_HASH: {"alpha": _COMPONENT}})
    assert not facts and partial
    rows[0]["raw_line_truncated"] = 1
    assert _revision(rows) is None


def test_retained_contiguous_suffix_preserves_calls_but_not_unknown_root():
    rows = [_row(42, {"role": "assistant", "content": [_call("retained")]})]
    rows.append(_row(43, _result("retained")))
    assert _revision(rows) is None, "a missing prefix can never count as a complete source"
    assert _revision(rows, retained_suffix=True)
    facts, partial = _matched(PiInvocationExtractor().extract(rows), rows, {_HASH: {"alpha": _COMPONENT}})
    assert len(facts) == 1 and facts[0]["root_session_id"] is None and partial
    rows[1]["line_offset"] = 44
    assert _revision(rows, retained_suffix=True) is None, "an interior gap is not a safe retained segment"


def test_duplicate_call_ids_do_not_create_false_positive():
    rows = [_row(0, {"role": "assistant", "content": [_call("same"), _call("same")]}), _row(1, _result("same"))]
    facts, partial = _matched(PiInvocationExtractor().extract(rows), rows, {_HASH: {"alpha": _COMPONENT}})
    assert not facts and partial
