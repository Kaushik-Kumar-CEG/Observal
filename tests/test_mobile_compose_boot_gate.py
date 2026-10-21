# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Compose services cannot reuse a retained init success after a DB restore."""

import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
SOURCES = (ROOT / "docker/docker-compose.yml", ROOT / "docker/server-package/docker-compose.yml")


@pytest.mark.parametrize("compose_file", SOURCES, ids=["main", "standalone"])
def test_every_api_replica_and_worker_check_database_again_before_start(compose_file):
    services = yaml.safe_load(compose_file.read_text())["services"]
    init, api, worker = (services[f"observal-{role}"] for role in ("init", "api", "worker"))
    assert init["command"] == ["/app/entrypoint.sh"]
    assert init["image"] == api["image"] == worker["image"]
    for service in (api, worker):
        assert service["depends_on"]["observal-init"]["condition"] == "service_completed_successfully"
        assert service["entrypoint"] == [
            "/bin/sh",
            "-ec",
            '/app/.venv/bin/python -m services.mobile_boot_preflight --require-schema && exec "$@"',
            "--",
        ]


@pytest.mark.parametrize("exit_code", [0, 2])
def test_boot_wrapper_execs_only_after_schema_and_clock_check(tmp_path, exit_code):
    # Test shell argument forwarding and fail-closed behavior separately from
    # the mocked SQL checks in test_mobile_boot_preflight.py. No Docker/DB.
    probe = tmp_path / "probe"
    probe.write_text(f"#!/bin/sh\nexit {exit_code}\n")
    probe.chmod(0o700)
    started = tmp_path / "started"
    launcher = tmp_path / "launch"
    launcher.write_text(f"#!/bin/sh\nprintf %s \"$1\" > '{started}'\n")
    launcher.chmod(0o700)
    result = subprocess.run(
        ["/bin/sh", "-ec", f'{probe} && exec "$@"', "--", str(launcher), "real-command"],
        check=False,
        capture_output=True,
        timeout=5,
    )
    assert result.returncode == exit_code
    assert started.exists() == (exit_code == 0)
    if exit_code == 0:
        assert started.read_text() == "real-command"
