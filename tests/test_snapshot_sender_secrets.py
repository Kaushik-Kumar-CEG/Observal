# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0

"""Snapshot uploads must not ship user configuration contents."""

from types import SimpleNamespace

from observal_cli import layer
from observal_cli.sessions import base


def test_cli_snapshot_outgoing_body_omits_secret_file(monkeypatch, tmp_path):
    secret = "outbound-cli-settings-credential-sentinel"
    lock_name_secret = "outbound-cli-lockfile-name-credential-sentinel"
    path = tmp_path / "settings.local.json"
    path.write_text('{"api_key":"' + secret + '"}')
    monkeypatch.setattr(
        layer, "_discover_files", lambda _harness, _project: [(path, "project:.claude/settings.local.json")]
    )
    monkeypatch.setattr(layer, "_load_hash_cache", lambda: {})
    monkeypatch.setattr(layer, "_save_hash_cache", lambda _cache: None)
    monkeypatch.setattr(layer, "_get_observal_managed_files", lambda *_args: set())
    monkeypatch.setattr(
        "observal_cli.lockfile.read_registry_lockfile",
        lambda: (
            None,
            {
                "harnesses": {
                    "claude-code": {
                        "agents": [],
                        "standalone": [
                            {
                                "type": "mcp",
                                "id": "11111111-1111-4111-8111-111111111111",
                                "version": "1.0.0",
                                "name": lock_name_secret,
                            }
                        ],
                    }
                }
            },
        ),
    )
    monkeypatch.setattr("observal_cli.lockfile.compute_lockfile_hash", lambda: "none")
    monkeypatch.setattr(
        layer,
        "_compute_drift",
        lambda *_args: {
            "is_canonical": False,
            "drifted_files": [{"path": lock_name_secret, "component": lock_name_secret}],
        },
    )
    monkeypatch.setattr(layer, "needs_upload", lambda _hash: True)
    monkeypatch.setattr(layer, "save_local_snapshot", lambda _payload: None)

    request_bodies = []

    class Client:
        def __init__(self, **_kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            pass

        def post(self, url, json, headers):
            request_bodies.append((url, json, headers))
            return SimpleNamespace(status_code=200)

    monkeypatch.setattr("httpx.Client", Client)
    base._maybe_upload_layer_snapshot(
        "https://example.test", "test-token", "anyhash12345", "claude-code", str(tmp_path)
    )
    assert len(request_bodies) == 1
    url, payload, headers = request_bodies[0]
    assert url == "https://example.test/api/v1/layer-snapshots"
    assert headers["Authorization"] == "Bearer test-token"
    file_entry = payload["harnesses"]["claude-code"][0]
    assert file_entry["hash"].startswith("sha256-")
    assert "content" not in file_entry
    assert payload["pinned_versions"] == {"agents": [], "standalone": []}
    assert payload["drift"] == {"is_canonical": False, "drifted_files": []}
    assert secret not in str(payload)
    assert lock_name_secret not in str(payload)
