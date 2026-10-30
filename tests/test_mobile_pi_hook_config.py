# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Pi agent pull emits only hook entries the v3 sender can execute and pin."""

from services.harness.pi import pi_hook_entries


def _hook(**changes):
    return {
        "name": "test",
        "event": "PreToolUse",
        "handler_type": "command",
        "handler_config": {"command": "exit 0", "timeout": 2},
        "tool_filter": None,
        "registry_id": "a11c01d1-1111-4111-8111-111111111111",
        "registry_version": "1.0.0",
        **changes,
    }


def test_only_pinned_user_scope_inline_hooks_are_generated():
    entries, warnings = pi_hook_entries([_hook()], "user")
    assert not warnings
    assert entries == [
        {
            "id": "a11c01d1-1111-4111-8111-111111111111",
            "version": "1.0.0",
            "name": "test",
            "event": "tool_call",
            "type": "command",
            "command": "exit 0",
            "timeout": 2,
        }
    ]
    assert pi_hook_entries([_hook()], "project")[0] == []
    assert pi_hook_entries([_hook(tool_filter="read")], "user")[0] == []
    assert pi_hook_entries([_hook(registry_id=None)], "user")[0] == []
    assert pi_hook_entries([_hook(script_filename="run.sh")], "user")[0] == []
    assert pi_hook_entries([_hook(event="SessionStart")], "user")[0] == []
    assert pi_hook_entries([_hook(handler_type="http")], "user")[0] == []
    assert pi_hook_entries([_hook(), _hook()], "user")[0] == []
