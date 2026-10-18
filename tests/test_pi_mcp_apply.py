# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Pi MCP identity is recorded only after an actual, private on-disk apply."""

import hashlib
import json
import uuid
from pathlib import Path
from unittest.mock import Mock

import pytest

from observal_cli import lockfile
from observal_cli.pi_mcp_apply import apply_pi_mcp


def _release():
    listing_id, version_id = str(uuid.uuid4()), str(uuid.uuid4())
    return (
        {
            "listing_id": listing_id,
            "version_id": version_id,
            "version": "1.0.0",
            "digest": "sha256:" + "b" * 64,
            "config_snippet": {"mcpServers": {"test-mcp": {"command": "echo", "args": ["hello"], "env": {}}}},
        },
        {"id": listing_id, "name": "Test MCP", "namespace": "test", "slug": "test-mcp"},
    )


def test_pi_mcp_applies_exact_entry_before_recording_identity(tmp_path, monkeypatch):
    result, listing = _release()
    root = tmp_path / ".pi" / "agent"
    root.mkdir(parents=True)
    (root / "mcp.json").write_text(json.dumps({"mcpServers": {"existing": {"command": "true"}}, "other": 1}))
    recorder = Mock(side_effect=lambda *_args, **_kwargs: json.loads((root / "mcp.json").read_text()))
    monkeypatch.setattr(lockfile, "upsert_standalone", recorder)
    assert apply_pi_mcp(result, listing, home=tmp_path) == "test-mcp"
    config = json.loads((root / "mcp.json").read_text())
    assert config["other"] == 1 and len(config["mcpServers"]) == 2
    assert config["mcpServers"]["test-mcp"] == result["config_snippet"]["mcpServers"]["test-mcp"]
    assert (root / "mcp.json").stat().st_mode & 0o777 == 0o600
    assert recorder.call_count == 1
    assert recorder.call_args.kwargs["component_id"] == listing["id"]
    assert recorder.call_args.kwargs["digest"] == result["digest"]
    assert (
        recorder.call_args.kwargs["config_sha256"]
        == hashlib.sha256(
            json.dumps(config["mcpServers"]["test-mcp"], sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
    )


def test_pi_mcp_refuses_collision_symlink_and_unpinned_response_before_identity(tmp_path, monkeypatch):
    result, listing = _release()
    recorder = Mock()
    monkeypatch.setattr(lockfile, "upsert_standalone", recorder)
    root = tmp_path / ".pi" / "agent"
    root.mkdir(parents=True)
    path = root / "mcp.json"
    path.write_text(json.dumps({"mcpServers": {"test-mcp": {"command": "different"}}}))
    with pytest.raises(ValueError, match="alias already exists"):
        apply_pi_mcp(result, listing, home=tmp_path)
    path.unlink()
    target = tmp_path / "target"
    target.write_text("secret")
    path.symlink_to(target)
    with pytest.raises(ValueError, match="symlinked"):
        apply_pi_mcp(result, listing, home=tmp_path)
    path.unlink()
    result["digest"] = None
    with pytest.raises(ValueError, match="digest"):
        apply_pi_mcp(result, listing, home=tmp_path)
    assert not path.exists() and recorder.call_count == 0
    assert Path(target).read_text() == "secret"
