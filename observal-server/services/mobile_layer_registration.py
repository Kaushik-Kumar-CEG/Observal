# SPDX-FileCopyrightText: 2026 Observal Contributors
# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Bind mobile Pi pins to the uploader's authenticated, v2-verified source layer.

The snapshot was already checked against its v2 content/pin hash on upload.
A typed mapping must never be inferred from an approved listing alone: the
same uploader must have a verified active Pi binding in that exact layer.
"""

import re

from services.layer_components.normalizer import normalize_snapshot

_HASH = re.compile(r"[0-9a-f]{64}\Z")
_PI_MCP_SOURCES = (
    "user:.config/mcp/mcp.json",
    "user:.agents/mcp.json",
    "user:.agents/mcp/mcp.json",
    "user:mcp.json",
    "user:mcp-adapter.json",
    "project:.mcp.json",
    "project:.pi/mcp.json",
    "project:.pi/mcp-adapter.json",
)
_VERIFIER = {
    "mcp": "observal:mcp-verification",
    "skill": "observal:skill-verification",
    "hook": "observal:hook-verification",
}


def matches_verified_pi_snapshot(snapshot: dict, layer: object) -> bool:
    """Reject missing, ambiguous, drifted or unbound pins, including extra claims."""
    if not isinstance(snapshot, dict) or snapshot.get("hash_schema_version") != 2:
        return False
    manifest = snapshot.get("harnesses", {}).get("pi")
    if not isinstance(manifest, list):
        return False
    files = {entry.get("path"): entry.get("hash") for entry in manifest if isinstance(entry, dict)}
    if len(files) != len(manifest):
        return False
    pins = snapshot.get("pinned_versions")
    if not isinstance(pins, dict) or pins.get("schema_version") != 2:
        return False
    occurrences = [item for item in normalize_snapshot(pins, snapshot.get("drift")) if item.harness == "pi"]
    claimed = (
        [("mcp", str(pin.id), pin.version, pin.alias, "") for pin in layer.components]
        + [("skill", str(pin.id), pin.version, pin.alias, pin.scope) for pin in layer.skills]
        + [("hook", str(pin.id), pin.version, pin.alias, pin.scope) for pin in layer.hooks]
    )
    if not claimed or len(occurrences) != len(claimed) or len(set(claimed)) != len(claimed):
        return False
    remaining = list(occurrences)
    for kind, component_id, version, alias, scope in claimed:
        candidates = [
            item
            for item in remaining
            if item.component_type == kind
            and item.raw_listing_id == component_id
            and item.raw_version == version
            and item.local_name == alias
            and (not scope or item.scope == scope)
        ]
        if len(candidates) != 1 or candidates[0].verification_status != "verified":
            return False
        item = candidates[0]
        remaining.remove(item)
        if not re.fullmatch(r"sha256-[0-9a-f]{64}", files.get(_VERIFIER[kind], "")):
            return False
        if kind == "mcp" and not any(
            re.fullmatch(r"sha256-[0-9a-f]{64}", files.get(path, "")) for path in _PI_MCP_SOURCES
        ):
            return False
        if kind == "skill":
            pin = next(pin for pin in layer.skills if str(pin.id) == component_id)
            path = ("user:skills/" if pin.scope == "user" else "project:.pi/skills/") + alias + "/SKILL.md"
            if item.location_sha256 != pin.location_sha256 or files.get(path) != "sha256-" + pin.content_sha256:
                return False
        if kind == "hook":
            pin = next(pin for pin in layer.hooks if str(pin.id) == component_id)
            if (
                item.scope != "user"
                or item.location_sha256 != pin.binding_sha256
                or not _HASH.fullmatch(pin.binding_sha256)
            ):
                return False
            if not re.fullmatch(r"sha256-[0-9a-f]{64}", files.get("user:observal-hooks.json", "")):
                return False
    return not remaining
