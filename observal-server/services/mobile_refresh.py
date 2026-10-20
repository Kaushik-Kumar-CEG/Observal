# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Atomic, non-replayable mobile refresh predecessor -> successor exchange.

Only opaque JTI keys and account/device revocation markers are read or written.
No raw token or successor response is cached in Redis. A lost reply therefore
requires exceptional fresh device approval, not replay of a spent predecessor.
"""

_ROTATE = """
-- mobile-refresh-rotation-v1
local previous = redis.call('GET', KEYS[1])
if previous ~= ARGV[1] then return 0 end
local marker = redis.call('GET', KEYS[3])
if marker then
  local epoch = tonumber(marker)
  if not epoch or epoch < 1000000000 or not tonumber(ARGV[2])
    or tonumber(ARGV[2]) < epoch then return -1 end
end
if redis.call('EXISTS', KEYS[4]) ~= 0 then return -1 end
if redis.call('EXISTS', KEYS[2]) ~= 0 then return -1 end
local ttl = tonumber(ARGV[3])
if not ttl or ttl < 1 then return -1 end
if redis.call('SET', KEYS[2], ARGV[1], 'EX', ttl, 'NX') == false then return -1 end
redis.call('DEL', KEYS[1])
return 1
"""


async def rotate_mobile_refresh(
    redis, *, user_id: str, device_id: str, previous_jti: str, successor_jti: str, issued_us: int, ttl: int
) -> int:
    """1=committed; 0=spent/missing; -1=revoked/collision. Redis errors propagate fail-closed.

    Redis executes the script atomically across workers; the caller holds the
    mobile project's PostgreSQL shared issue lock until the response returns.
    The successor TTL cannot exceed the old JWT's immutable family expiry.
    """
    return int(
        await redis.eval(
            _ROTATE,
            4,
            f"refresh_jti:{previous_jti}",
            f"refresh_jti:{successor_jti}",
            f"revoked_user:{user_id}",
            f"revoked_mobile_device:{device_id}",
            user_id,
            str(issued_us),
            str(ttl),
        )
    )
