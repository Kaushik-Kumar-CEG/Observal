# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Apply one exact registry MCP version to the active Pi MCP adapter config.

Only after an atomic on-disk readback is a registry pin recorded. Pi's sender
independently requires both the lockfile pin and an active mcp.json alias;
this cannot attest to a successful remote MCP handshake or tool call.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from pathlib import Path
from uuid import UUID

from observal_cli import lockfile

_ALIAS = re.compile(r"^[A-Za-z0-9_-]{1,128}$")


def apply_pi_mcp(result: dict, listing: dict, *, home: Path | None = None) -> str:
    """Install the generated Pi snippet, verify bytes, then record the exact pin."""
    snippet = result.get("config_snippet")
    servers = snippet.get("mcpServers") if isinstance(snippet, dict) else None
    if not isinstance(servers, dict) or len(servers) != 1:
        raise ValueError("Pi install response must contain exactly one MCP entry")
    alias, entry = next(iter(servers.items()))
    if not isinstance(alias, str) or not _ALIAS.fullmatch(alias) or not isinstance(entry, dict):
        raise ValueError("Invalid Pi MCP alias or entry")
    listing_id = str(UUID(result["listing_id"]))
    version_id = str(UUID(result["version_id"]))
    version, digest = result.get("version"), result.get("digest")
    if not isinstance(version, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+_-]{0,49}", version):
        raise ValueError("No exact registry version in Pi install response")
    if not isinstance(digest, str) or not re.fullmatch(r"sha256:[a-f0-9]{64}", digest):
        raise ValueError("No verified registry digest in Pi install response")
    if listing.get("id") != listing_id or not all(
        isinstance(listing.get(k), str) for k in ("namespace", "slug", "name")
    ):
        raise ValueError("Registry listing/response mismatch")
    root = (home or Path.home()) / ".pi" / "agent"
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = root / "mcp.json"
    if root.is_symlink() or path.is_symlink():
        raise ValueError("Refusing a symlinked Pi MCP configuration")
    with lockfile._exclusive_lock(root / ".observal-mcp.lock"):
        if path.exists():
            if not path.is_file() or path.stat().st_size > 1024 * 1024:
                raise ValueError("Pi MCP configuration is not a bounded regular file")
            config = json.loads(path.read_text())
            if not isinstance(config, dict) or not isinstance(config.get("mcpServers"), dict):
                raise ValueError("Invalid existing Pi MCP configuration")
        else:
            config = {"mcpServers": {}}
        active = config["mcpServers"]
        if alias in active and active[alias] != entry:
            raise ValueError("Pi MCP alias already exists with different configuration; resolve collision first")
        active[alias] = entry
        payload = json.dumps(config, indent=2, ensure_ascii=False) + "\n"
        fd, tmp = tempfile.mkstemp(prefix=".mcp-", suffix=".tmp", dir=root)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as output:
                output.write(payload)
                output.flush()
                os.fsync(output.fileno())
            os.chmod(tmp, 0o600)
            os.replace(tmp, path)
            if os.name == "posix":
                directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
        finally:
            Path(tmp).unlink(missing_ok=True)
        if json.loads(path.read_text()).get("mcpServers", {}).get(alias) != entry:
            raise RuntimeError("Pi MCP installation did not persist")
        lockfile.upsert_standalone(
            "pi",
            component_type="mcp",
            name=listing["name"],
            component_id=listing_id,
            version=version,
            scope="user",
            namespace=listing["namespace"],
            slug=listing["slug"],
            local_name=alias,
            version_id=version_id,
            digest=digest,
            config_sha256=hashlib.sha256(
                json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
            ).hexdigest(),
        )
    return alias
