# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Redis-backed revocation must survive memory pressure on every install path."""

import os
from pathlib import Path
from urllib.parse import urlparse

import pytest
from redis.asyncio import Redis
from redis.exceptions import OutOfMemoryError

ROOT = Path(__file__).resolve().parents[1]
POLICIES = (
    "docker/docker-compose.yml",
    "observal_cli/server/config_gen.py",
    "infra/terraform/aws-standard/data-user-data.sh.tftpl",
    "infra/terraform/azure/cloud-init.yaml.tftpl",
    "infra/terraform/gcp/memorystore.tf",
    "infra/helm/observal/templates/redis-statefulset.yaml",
)


@pytest.mark.parametrize("path", POLICIES)
def test_installed_redis_policy_cannot_evict_access_revocation(path):
    content = (ROOT / path).read_text()
    assert "noeviction" in content, path
    assert "allkeys-lru" not in content and "volatile-lru" not in content, path


@pytest.mark.asyncio
async def test_disposable_redis_out_of_memory_never_erases_revocation():
    """Opt-in only: require a distinct loopback scratch container, not the server Redis."""
    url = os.getenv("MOBILE_REDIS_EVICTION_SCRATCH_URL")
    if not url:
        pytest.skip("requires disposable loopback Redis on port 15441")
    parsed = urlparse(url)
    assert (parsed.scheme, parsed.hostname, parsed.port) == ("redis", "127.0.0.1", 15441)
    redis = Redis.from_url(url, decode_responses=True)
    try:
        assert await redis.config_get("maxmemory-policy") == {"maxmemory-policy": "noeviction"}
        # A user-wide marker has no TTL; mobile device/JTI markers do.
        await redis.set("revoked_user:synthetic-capacity", "1777777777777777")
        await redis.set("revoked_mobile_device:synthetic-capacity", "1", ex=3600)
        await redis.set("revoked_jti:synthetic-capacity", "1", ex=3600)
        assert await redis.ttl("revoked_user:synthetic-capacity") == -1
        rejected = False
        for index in range(1500):
            try:
                await redis.set(f"scratch:memory:{index}", "x" * 8192, ex=60)
            except OutOfMemoryError:
                rejected = True
                break
        assert rejected, "scratch Redis was not filled to its test-only 4 MiB cap"
        assert await redis.get("revoked_user:synthetic-capacity") == "1777777777777777"
        assert await redis.get("revoked_mobile_device:synthetic-capacity") == "1"
        assert await redis.get("revoked_jti:synthetic-capacity") == "1"
        assert int((await redis.info("stats"))["evicted_keys"]) == 0
    finally:
        await redis.aclose()
