# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Proxy must not pin a Docker service address across container recreation."""

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1] / "docker"


@pytest.mark.parametrize("name", ["nginx.conf", "nginx.dev.conf", "nginx.production.conf"])
def test_docker_proxies_refresh_api_and_web_service_ips(name: str):
    config = (ROOT / name).read_text()
    assert "resolver 127.0.0.11 valid=5s ipv6=off;" in config
    assert "zone observal_api 64k;" in config
    assert "server observal-api:8000 resolve;" in config
    assert "zone observal_web 64k;" in config
    assert "server observal-web:3000 resolve;" in config
    assert "proxy_pass http://observal_api;" in config
    assert "proxy_pass http://observal_web;" in config
