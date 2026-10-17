# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Pi extension hook receipts; client-reported, never independent launcher proof."""

import json
import re
from dataclasses import dataclass
from datetime import datetime

from services.mobile_pi_skill_loads import _time

_ID = re.compile(r"[\x21-\x7e]{1,256}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_NESTED = re.compile(r"([^/]+)(?:/[0-9]{1,6})+\Z")
_EVENTS = {"tool_call", "tool_result"}
_OUTCOMES = {"ran", "ran_with_output", "failed", "blocked"}


@dataclass(frozen=True)
class HookReceipt:
    offset: int
    block_key: str
    binding_sha256: str
    event: str
    outcome: str
    event_time: datetime
    layer_hash: str | None


def extract_hook_receipts(rows: list[dict]) -> tuple[list[HookReceipt], bool]:
    parsed = []
    malformed = False
    for row in rows:
        try:
            record = json.loads(row["raw_line"])
        except (ValueError, TypeError, KeyError):
            malformed = True
            continue
        if not isinstance(record, dict):
            malformed = True
            continue
        parsed.append((row["line_offset"], row.get("layer_hash"), record))
    parsed.sort(key=lambda record: record[0])
    calls: dict[str, list[tuple[int, str | None]]] = {}
    results: dict[str, list[tuple[int, bool, str | None]]] = {}
    for offset, generation, record in parsed:
        msg = record.get("message")
        if record.get("type") != "message" or not isinstance(msg, dict):
            continue
        if msg.get("role") == "assistant" and isinstance(msg.get("content"), list):
            for block in msg["content"]:
                if isinstance(block, dict) and block.get("type") == "toolCall" and isinstance(block.get("id"), str):
                    calls.setdefault(block["id"], []).append((offset, generation))
        elif msg.get("role") == "toolResult" and isinstance(msg.get("toolCallId"), str):
            # A malformed duplicate is still a result for uniqueness checks;
            # ignoring it would allow an ambiguous hook run to qualify.
            is_error = msg.get("isError")
            results.setdefault(msg["toolCallId"], []).append(
                (offset, is_error if isinstance(is_error, bool) else None, generation)
            )
    facts = []
    seen = set()
    for offset, generation, record in parsed:
        if record.get("type") != "custom" or record.get("customType") != "observal-hook-run":
            continue
        data = record.get("data")
        if not isinstance(data, dict) or type(data.get("v")) is not int or data["v"] != 1:
            malformed = True
            continue
        event, call, binding = data.get("event"), data.get("tool_call_id"), data.get("binding")
        outcome, code = data.get("outcome"), data.get("exit_code")
        stamp = _time(record.get("timestamp"))
        if (
            event not in _EVENTS
            or not isinstance(call, str)
            or not _ID.fullmatch(call)
            or not isinstance(binding, str)
            or not _DIGEST.fullmatch(binding)
            or outcome not in _OUTCOMES
            or (code is not None and type(code) is not int)
            or (outcome in ("ran", "ran_with_output") and code != 0)
            or (outcome == "blocked" and (event != "tool_call" or code != 2))
            or (outcome == "failed" and code == 0)
            or stamp is None
        ):
            malformed = True
            continue
        nested = _NESTED.fullmatch(call)
        root_call = nested.group(1) if nested else call
        made = calls.get(root_call, [])
        linked = results.get(call, [])
        if (
            len(made) != 1
            or made[0][0] >= offset
            or made[0][1] != generation
            or (event == "tool_result" and (len(linked) != 1 or linked[0][0] <= offset))
            or any(error is None for _, error, _ in linked)
            or (outcome == "blocked" and any(error is False for _, error, _ in linked))
            or any(result_generation != generation for _, _, result_generation in linked)
        ):
            malformed = True
            continue
        key = (event, call, binding)
        if key in seen:
            continue
        seen.add(key)
        facts.append(HookReceipt(offset, "hook-run:0", binding, event, outcome, stamp, generation))
    return facts, malformed
