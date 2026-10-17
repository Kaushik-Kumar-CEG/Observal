# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Source-record Pi skill *loads*, never availability or slash-command guesses.

Pi's system skills advertisement and a successful linked read are necessary;
only the caller's exact uploader-bound, approved, fingerprinted install may
turn a load into a mobile fact. The Pi transcript is still client-reported.
"""

import hashlib
import json
import posixpath
import re
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime

_ALIAS = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
_ADVERTISED = re.compile(r"<skill>\s*<name>(.*?)</name>.*?<location>(.*?)</location>\s*</skill>", re.S)
_USER_LAYOUT = re.compile(r"/\.pi/agent/skills/([^/]+)/SKILL\.md\Z")


@dataclass(frozen=True)
class SkillLoad:
    offset: int
    block_key: str
    scope: str
    alias: str
    location_sha256: str
    content_sha256: str
    event_time: datetime
    layer_hash: str | None


def _time(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return stamp.astimezone(UTC) if stamp.tzinfo is not None and 1971 <= stamp.year < 2100 else None


def _install(location: str, cwd: str) -> tuple[str, str] | None:
    if len(location) > 4096 or not location.startswith("/") or posixpath.normpath(location) != location:
        return None
    user = _USER_LAYOUT.search(location)
    if user:
        scope, alias = "user", user.group(1)
    elif (
        cwd.startswith("/") and posixpath.normpath(cwd) == cwd and location.startswith(cwd.rstrip("/") + "/.pi/skills/")
    ):
        scope = "project"
        parts = location[len(cwd.rstrip("/") + "/.pi/skills/") :].split("/")
        if len(parts) != 2 or parts[1] != "SKILL.md":
            return None
        alias = parts[0]
    else:
        return None
    return (scope, alias) if _ALIAS.fullmatch(alias) else None


def extract_skill_loads(rows: list[dict]) -> tuple[list[SkillLoad], bool]:
    """Bind an advertised location at call time to one later successful result.

    Ambiguous call IDs, duplicate advertised aliases, errors, truncated or
    malformed records produce no positive fact; callers retain Partial status.
    """
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
    parsed.sort(key=lambda item: item[0])
    cwd = next((record.get("cwd") for _, _, record in parsed if record.get("type") == "session"), "")
    cwd = cwd if isinstance(cwd, str) else ""
    advertised: dict[str, tuple[str, str]] = {}
    calls: list[tuple[int, int, str, str, str, str, datetime | None, str | None]] = []
    results: dict[str, list[tuple[int, bool, str | None, str | None]]] = {}
    advertised_generation = None
    for offset, generation, record in parsed:
        if record.get("type") != "message" or not isinstance(record.get("message"), dict):
            continue
        message = record["message"]
        role = message.get("role")
        if role == "system":
            section = message.get("sections")
            skills = section.get("skills") if isinstance(section, dict) else None
            advertised = {}
            advertised_generation = generation
            if isinstance(skills, str) and len(skills) <= 131072:
                candidates = _ADVERTISED.findall(skills)[:512]
                installs = [
                    (location.strip(), _install(location.strip(), cwd), name.strip()) for name, location in candidates
                ]
                aliases = Counter(pair[1] for pair in installs if pair[1] is not None)
                for location, install, name in installs:
                    if install and name == install[1] and aliases[install] == 1:
                        advertised[location] = install
        elif role == "assistant" and isinstance(message.get("content"), list):
            for index, block in enumerate(message["content"]):
                if not isinstance(block, dict) or block.get("type") != "toolCall" or block.get("name") != "read":
                    continue
                args = block.get("arguments")
                location = args.get("path") if isinstance(args, dict) else None
                call_id = block.get("id")
                if isinstance(location, str) and location.endswith("/SKILL.md") and location not in advertised:
                    malformed = True  # A skill-shaped read without a verified advertisement is unknown, not zero.
                if (
                    isinstance(location, str)
                    and location in advertised
                    and isinstance(call_id, str)
                    and 0 < len(call_id) <= 256
                    and isinstance(args, dict)
                    and args.get("offset") is None
                    and args.get("limit") is None
                ):
                    scope, alias = advertised[location]
                    calls.append(
                        (
                            offset,
                            index,
                            call_id,
                            scope,
                            alias,
                            location,
                            _time(record.get("timestamp")),
                            generation if generation == advertised_generation else None,
                        )
                    )
        elif role == "toolResult":
            call_id = message.get("toolCallId")
            if isinstance(call_id, str):
                # Every result for a call ID participates in uniqueness, even a
                # malformed result. Otherwise a valid read followed by an
                # ambiguous duplicate would still qualify the skill load.
                is_error = message.get("isError")
                content = message.get("content")
                text = (
                    content[0].get("text")
                    if isinstance(content, list)
                    and len(content) == 1
                    and isinstance(content[0], dict)
                    and content[0].get("type") == "text"
                    else None
                )
                digest = None
                if message.get("toolName") == "read" and isinstance(text, str) and not message.get("details"):
                    try:
                        encoded = text.encode("utf-8")
                    except UnicodeError:
                        pass  # Malformed source text is unqualified, not a worker retry loop.
                    else:
                        if len(encoded) <= 262144:
                            digest = hashlib.sha256(encoded).hexdigest()
                results.setdefault(call_id, []).append(
                    (offset, is_error if isinstance(is_error, bool) else None, generation, digest)
                )
    counts = Counter(call[2] for call in calls)
    facts = []
    for offset, index, call_id, scope, alias, location, stamp, generation in calls:
        linked = results.get(call_id, [])
        if (
            counts[call_id] != 1
            or len(linked) != 1
            or linked[0][0] <= offset
            or linked[0][1] is not False
            or linked[0][2] != generation
            or linked[0][3] is None
            or stamp is None
        ):
            malformed = True
            continue
        facts.append(
            SkillLoad(
                offset,
                f"skill-load:{index}",
                scope,
                alias,
                hashlib.sha256(location.encode()).hexdigest(),
                linked[0][3],
                stamp,
                generation,
            )
        )
    return facts, malformed
