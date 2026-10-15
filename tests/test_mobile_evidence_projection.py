# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Never turn unverified or malformed client evidence into a measured zero."""

import json
import uuid

from jobs.mobile_evidence import _matched, _revision
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


def test_forty_independently_linked_calls_one_logical_root():
    # One assistant line can contain multiple calls. A summary-row tool count
    # would undercount these 40 events as only one.
    rows = [_row(0, {"role": "user", "content": "real prompt"}, event_type="user_prompt")]
    rows += [_row(1, {"role": "assistant", "content": [_call(f"c{i}") for i in range(40)]})]
    rows += [_row(i + 2, _result(f"c{i}")) for i in range(40)]
    extracted = PiInvocationExtractor().extract(rows)
    facts, partial = _matched(extracted, rows, {_HASH: {"alpha": _COMPONENT}})
    assert len(facts) == 40 and not partial
    assert len({(r["source_line_offset"], r["block_key"]) for r in facts}) == 40
    assert {r["root_session_id"] for r in facts} == {"session-1"}
    assert len({r["event_time"].date() for r in facts}) == 1
    assert _revision(rows) == _revision(list(rows)), "identical retries keep one revision"


def test_unprompted_calls_have_no_qualified_root_or_trace():
    rows = [_row(0, {"role": "assistant", "content": [_call("id")]}), _row(1, _result("id"))]
    facts, partial = _matched(PiInvocationExtractor().extract(rows), rows, {_HASH: {"alpha": _COMPONENT}})
    assert len(facts) == 1 and facts[0]["root_session_id"] is None and partial


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
