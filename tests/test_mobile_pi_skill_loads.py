# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Source-linked Pi read results are the only skill-load candidates."""

import hashlib
import json
import uuid
from datetime import UTC, datetime

from jobs.mobile_evidence import _matched_skill_loads
from services.mobile_pi_skill_loads import extract_skill_loads

LOCATION = "/home/synthetic/.pi/agent/skills/review/SKILL.md"
TIME = datetime.now(UTC).isoformat()


def _source(*records):
    return [{"line_offset": offset, "raw_line": json.dumps(record)} for offset, record in enumerate(records)]


def _header():
    return {"type": "session", "cwd": "/work"}


def _system(location=LOCATION):
    return {
        "type": "message",
        "timestamp": TIME,
        "message": {
            "role": "system",
            "sections": {
                "skills": (
                    f"<available_skills><skill><name>review</name><description>untrusted</description>"
                    f"<location>{location}</location></skill></available_skills>"
                )
            },
        },
    }


def _read(location=LOCATION, call_id="call1"):
    return {
        "type": "message",
        "timestamp": TIME,
        "message": {
            "role": "assistant",
            "content": [
                {
                    "type": "toolCall",
                    "name": "read",
                    "id": call_id,
                    "arguments": {"path": location},
                }
            ],
        },
    }


def _result(call_id="call1", error=False):
    return {
        "type": "message",
        "timestamp": TIME,
        "message": {"role": "toolResult", "toolCallId": call_id, "isError": error, "content": []},
    }


def test_advertised_exact_file_and_unique_later_success_are_a_candidate():
    loads, malformed = extract_skill_loads(_source(_header(), _system(), _read(), _result()))
    assert not malformed and len(loads) == 1
    assert (loads[0].offset, loads[0].block_key, loads[0].scope, loads[0].alias) == (
        2,
        "skill-load:0",
        "user",
        "review",
    )
    assert loads[0].location_sha256 == hashlib.sha256(LOCATION.encode()).hexdigest()


def test_installation_prompt_failure_duplicate_and_shadow_are_never_a_load():
    prompt = {
        "type": "message",
        "timestamp": TIME,
        "message": {"role": "user", "content": [{"type": "text", "text": f"/skill:review {LOCATION}"}]},
    }
    for records in (
        (_header(), _system(), prompt),
        (_header(), _read(), _result()),
        (_header(), _system(), _read(), _result(error=True)),
        (_header(), _system(), _read(), _result(), _result()),
        (_header(), _system(), _read(LOCATION + "-other"), _result()),
        (
            _header(),
            _system("/work/.pi/skills/review/../review/SKILL.md"),
            _read("/work/.pi/skills/review/../review/SKILL.md"),
            _result(),
        ),
    ):
        loads, _ = extract_skill_loads(_source(*records))
        assert not loads


def test_skill_and_mcp_same_verified_root_are_two_facts_but_one_actor_root_union():
    root = uuid.uuid4()
    skill_id = uuid.uuid4()
    source = _source(_header(), _system(), _read(), _result())
    for row in source:
        row["layer_hash"] = "v3_" + "a" * 64
    loads, _ = extract_skill_loads(source)
    mapping = {source[0]["layer_hash"]: {("user", "review"): (skill_id, loads[0].location_sha256)}}
    facts, partial = _matched_skill_loads(
        loads,
        source,
        mapping,
        revision="b" * 64,
        run_incarnation=root,
        root=root,
        root_session_id="root-session",
        root_start=loads[0].event_time,
    )
    assert not partial and len(facts) == 1
    assert facts[0]["component_id"] == skill_id
    assert facts[0]["source_revision"] == "b" * 64
    assert facts[0]["root_session_id"] == "root-session"
    assert facts[0]["root_run_incarnation"] == root
    # MCP and skill component rows overlap on one actor/root, not two people traces.
    mcp_fact = {"user_id": "actor", "root_run_incarnation": root, "component_id": uuid.uuid4()}
    assert len({("actor", fact["root_run_incarnation"]) for fact in (mcp_fact, facts[0])}) == 1
    for kwargs in (
        {"root": None},
        {"root_start": loads[0].event_time.replace(year=loads[0].event_time.year + 1)},
        {"run_incarnation": None},
    ):
        args = {
            "revision": "b" * 64,
            "run_incarnation": root,
            "root": root,
            "root_session_id": "root-session",
            "root_start": loads[0].event_time,
        }
        args.update(kwargs)
        denied, incomplete = _matched_skill_loads(loads, source, mapping, **args)
        assert not denied and incomplete
    source[2]["layer_hash"] = "v3_" + "c" * 64
    denied, incomplete = _matched_skill_loads(
        loads,
        source,
        mapping,
        revision="b" * 64,
        run_incarnation=root,
        root=root,
        root_session_id="root-session",
        root_start=loads[0].event_time,
    )
    assert not denied and incomplete
    source[2]["layer_hash"] = "v3_" + "a" * 64
    source[1]["layer_hash"] = "v3_" + "c" * 64
    loads, malformed = extract_skill_loads(source)
    assert not loads and malformed, "advertisement cannot predate a manifest generation swap"
    source[1]["layer_hash"] = "v3_" + "a" * 64
    source[3]["layer_hash"] = "v3_" + "c" * 64
    loads, malformed = extract_skill_loads(source)
    assert not loads and malformed, "result must confirm the same manifest generation"


def test_reload_revokes_old_advertised_path_and_blocks_late_read():
    removed = {"type": "message", "timestamp": TIME, "message": {"role": "system", "sections": {"skills": ""}}}
    loads, _ = extract_skill_loads(_source(_header(), _system(), removed, _read(), _result()))
    assert not loads
