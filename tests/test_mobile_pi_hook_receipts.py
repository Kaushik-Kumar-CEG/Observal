# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Only top-level same-generation, call-linked Pi receipts can count hook runs."""

import json
import uuid
from datetime import UTC, datetime

from jobs.mobile_evidence import _matched_hook_receipts
from services.mobile_pi_hook_receipts import extract_hook_receipts

STAMP = datetime.now(UTC).isoformat()
HASH = "v3_" + "a" * 64
BIND = "b" * 64


def _row(offset, record, generation=HASH):
    return {"line_offset": offset, "raw_line": json.dumps(record), "layer_hash": generation}


def _call():
    return _row(
        1,
        {
            "type": "message",
            "timestamp": STAMP,
            "message": {
                "role": "assistant",
                "content": [{"type": "toolCall", "id": "call1", "name": "read", "arguments": {"path": "/tmp/x"}}],
            },
        },
    )


def _receipt(*, outcome="ran", code=0, binding=BIND, offset=2, event="tool_call"):
    return _row(
        offset,
        {
            "type": "custom",
            "timestamp": STAMP,
            "customType": "observal-hook-run",
            "data": {
                "v": 1,
                "event": event,
                "tool_call_id": "call1",
                "binding": binding,
                "outcome": outcome,
                "exit_code": code,
            },
        },
    )


def test_silent_success_and_failure_receipts_are_positive_runs_and_deduped():
    source = [_call(), _receipt(), _receipt(offset=3)]
    facts, malformed = extract_hook_receipts(source)
    assert not malformed and len(facts) == 1
    assert facts[0].outcome == "ran" and facts[0].binding_sha256 == BIND
    failed, malformed = extract_hook_receipts([_call(), _receipt(outcome="failed", code=None)])
    assert not malformed and len(failed) == 1 and failed[0].outcome == "failed"


def test_pasted_or_unlinked_or_contradictory_receipt_never_counts():
    as_text = _row(
        2,
        {
            "type": "message",
            "timestamp": STAMP,
            "message": {
                "role": "user",
                "content": [{"type": "text", "text": json.dumps({"customType": "observal-hook-run", "binding": BIND})}],
            },
        },
    )
    assert not extract_hook_receipts([_call(), as_text])[0]
    bad_result = _row(
        3,
        {
            "type": "message",
            "timestamp": STAMP,
            "message": {
                "role": "toolResult",
                "toolCallId": "call1",
                "isError": False,
            },
        },
    )
    for rows in (
        [_receipt()],
        [_receipt(offset=0), _call()],
        [_call(), _receipt(outcome="blocked", code=2), bad_result],
        [_call(), _receipt(outcome="ran", code=2)],
        [_call(), _receipt(binding="0" * 63)],
        [_call(), {**_receipt(), "layer_hash": "v3_" + "c" * 64}],
        [_call(), _receipt(), {**bad_result, "layer_hash": "v3_" + "c" * 64}],
    ):
        facts, malformed = extract_hook_receipts(rows)
        assert not facts and malformed


def test_binding_and_prospective_root_are_required_for_a_hook_positive():
    header = _row(0, {"type": "session", "timestamp": STAMP, "cwd": "/work"})
    source = [header, _call(), _receipt()]
    receipt, malformed = extract_hook_receipts(source)
    assert len(receipt) == 1 and not malformed
    root = uuid.uuid4()
    component = uuid.uuid4()
    kwargs = {
        "revision": "1" * 64,
        "run_incarnation": root,
        "root": root,
        "root_session_id": "session",
        "root_start": receipt[0].event_time,
    }
    bound = {HASH: {BIND: (component, "tool_call")}}
    valid, partial = _matched_hook_receipts(receipt, source, bound, **kwargs)
    assert not partial and len(valid) == 1 and valid[0]["root_run_incarnation"] == root
    assert valid[0]["component_id"] == component
    for pins, override in (
        ({}, {}),
        ({HASH: {"c" * 64: (component, "tool_call")}}, {}),
        ({HASH: {BIND: (component, "tool_result")}}, {}),
        (bound, {"root": None}),
        (bound, {"run_incarnation": None}),
    ):
        denied, incomplete = _matched_hook_receipts(receipt, source, pins, **(kwargs | override))
        assert not denied and incomplete
    missing_prefix, partial = _matched_hook_receipts(receipt, source[1:], bound, **kwargs)
    assert not missing_prefix and partial


def test_unsupported_quiet_absence_is_not_positive_or_supported_zero():
    facts, malformed = extract_hook_receipts([_call()])
    assert not facts and not malformed
