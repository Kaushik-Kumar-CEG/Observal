#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Kaushik Kumar <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
set -Eeuo pipefail
umask 077
qa=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$qa/../../.." && pwd)
state_name=${MOBILE_FOLLOW_QA_STATE_NAME:-.runtime}
issuer_port=${MOBILE_FOLLOW_QA_PORT:-18443}
[[ "$state_name" == .runtime && "$issuer_port" == 18443 ]] || \
    [[ "$state_name" =~ ^\.runtime-scratch-[0-9a-f]{6,12}$ && "$issuer_port" == 18444 ]] || \
    [[ "$state_name" =~ ^\.runtime-android-[0-9a-f]{6,12}$ && "$issuer_port" == 18446 ]] || \
    [[ "$state_name" =~ ^\.runtime-android-next-[0-9a-f]{6,12}$ && "$issuer_port" == 18448 ]] || \
    [[ "$state_name" =~ ^\.runtime-android-diagnostic-[0-9a-f]{6,12}$ && "$issuer_port" == 18449 ]] || {
        echo 'Only default 18443, isolated 18444 scratch, old 18446 or independent 18448/18449 Android QA are allowed' >&2; exit 1;
    }
state="$qa/$state_name"
[[ ! -e "$state" && ! -L "$state" ]] || { echo 'QA already running or stale state; run down.sh first' >&2; exit 1; }
[[ -x "$repo/observal-server/.venv/bin/uvicorn" && -x "$repo/observal-server/.venv/bin/alembic" ]] || { echo 'Install server dependencies: cd observal-server && uv sync' >&2; exit 1; }
web_dist=${MOBILE_FOLLOW_QA_WEB_DIST:-$repo/web/dist}
[[ -d "$web_dist" && ! -L "$web_dist" && -s "$web_dist/index.html" ]] || {
    echo 'Build isolated current UI to a dedicated folder first; no shared QA assets are rebuilt' >&2; exit 1;
}
[[ ! -e "$repo/observal-server/.env" && ! -L "$repo/observal-server/.env" ]] || { echo 'Refusing to load server .env; use a clean isolated checkout' >&2; exit 1; }
for binary in docker openssl curl python3 node; do command -v "$binary" >/dev/null || { echo "missing $binary" >&2; exit 1; }; done
docker info >/dev/null
# Reject ANY preexisting listener on this port, including IPv6 (no listener is replaced).
python3 - "$issuer_port" <<'PY'
import socket, sys
port = int(sys.argv[1])
for family, address in ((socket.AF_INET, ('0.0.0.0', port)), (socket.AF_INET6, ('::', port))):
    with socket.socket(family) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # TIME_WAIT is not a listener
        if family == socket.AF_INET6: sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        sock.bind(address)
PY
mkdir -m 700 "$state"
id="followqa$(python3 -c 'import secrets; print(secrets.token_hex(5))')"
printf '%s\n' "$id" > "$state/id"
printf '%s\n' "$issuer_port" > "$state/issuer-port"
cleanup() { MOBILE_FOLLOW_QA_EXPECT_ID="$id" "$qa/down.sh" >/dev/null || true; }
started=0
trap 'if [[ $started == 0 ]]; then cleanup; fi' EXIT
run=$(mktemp -d /tmp/observal-follow-qa.XXXXXXXX)
printf '%s\n' "$run" > "$state/run"
# Root CA remains on host in 0700 temporary directory. Only leaf cert/key enter nginx.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -sha256 \
    -keyout "$run/ca.key" -out "$run/ca.crt" -subj '/CN=Disposable Follow QA CA' \
    -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign' >/dev/null 2>&1
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$run/leaf.key" -out "$run/leaf.csr" \
    -subj '/CN=localhost' >/dev/null 2>&1
printf '%s\n' 'subjectAltName=DNS:localhost' 'extendedKeyUsage=serverAuth' 'keyUsage=digitalSignature' > "$run/leaf.ext"
openssl x509 -req -in "$run/leaf.csr" -CA "$run/ca.crt" -CAkey "$run/ca.key" -CAcreateserial \
    -out "$run/leaf.crt" -days 2 -sha256 -extfile "$run/leaf.ext" >/dev/null 2>&1
# Random loopback-published ports, no named volumes. docker rm -v destroys all disposable data.
docker run -d --name "${id}pg" --label "observal.followqa.owner=$id" -p 127.0.0.1::5432 -e POSTGRES_USER=followqa \
    -e POSTGRES_PASSWORD=disposable-follow-qa -e POSTGRES_DB=followqa postgres:18 \
    postgres -c track_commit_timestamp=on >/dev/null
docker run -d --name "${id}redis" --label "observal.followqa.owner=$id" -p 127.0.0.1::6379 redis:7-alpine >/dev/null
docker run -d --name "${id}ch" --label "observal.followqa.owner=$id" -p 127.0.0.1::8123 \
    -e CLICKHOUSE_USER=followqa -e CLICKHOUSE_PASSWORD=disposable-follow-qa \
    -e CLICKHOUSE_DB=followqa clickhouse/clickhouse-server:26.6 >/dev/null
pgport=$(docker port "${id}pg" 5432/tcp | awk -F: '{print $NF}')
redisport=$(docker port "${id}redis" 6379/tcp | awk -F: '{print $NF}')
chport=$(docker port "${id}ch" 8123/tcp | awk -F: '{print $NF}')
# The ClickHouse entrypoint briefly starts a temporary server to create its user
# and database, then stops it before starting the final server. A single SELECT 1
# can hit that temporary process and fail immediately on the next query.
ready_streak=0
for _ in {1..90}; do
    if docker exec "${id}pg" pg_isready -q -U followqa && \
        docker exec "${id}redis" redis-cli ping 2>/dev/null | grep -q PONG && \
        docker exec "${id}ch" clickhouse-client --user followqa --password disposable-follow-qa \
            --query 'SELECT 1' >/dev/null 2>&1; then
        ready_streak=$((ready_streak + 1))
        (( ready_streak >= 5 )) && break
    else
        ready_streak=0
    fi
    sleep 1
done
(( ready_streak >= 5 )) || { echo 'Disposable PostgreSQL/Redis/ClickHouse never reached stable readiness' >&2; exit 1; }
docker exec "${id}pg" pg_isready -q -U followqa
docker exec "${id}redis" redis-cli ping | grep -q PONG
docker exec "${id}ch" clickhouse-client --user followqa --password disposable-follow-qa --query 'SELECT 1' >/dev/null
export DATABASE_URL="postgresql+asyncpg://followqa:disposable-follow-qa@127.0.0.1:$pgport/followqa"
export REDIS_URL="redis://127.0.0.1:$redisport/0"
export CLICKHOUSE_URL="http://followqa:disposable-follow-qa@127.0.0.1:$chport/followqa"
SECRET_KEY=$(openssl rand -hex 32)
export SECRET_KEY JWT_KEY_DIR="$run/jwt" SEED_DEMO_ACCOUNTS=false SKIP_DDL_ON_STARTUP=true
# Neither the parent shell nor a server .env may inject production service URLs or tokens.
isolated() {
    env -i PATH="$PATH" HOME="$HOME" LANG="${LANG:-C.UTF-8}" PYTHONPATH="$PWD" DATABASE_URL="$DATABASE_URL" \
        REDIS_URL="$REDIS_URL" CLICKHOUSE_URL="$CLICKHOUSE_URL" \
        SECRET_KEY="$SECRET_KEY" JWT_KEY_DIR="$JWT_KEY_DIR" QA_PASSWORD="${QA_PASSWORD:-}" \
        MOBILE_FOLLOW_LOCAL_QA=1 MOBILE_FOLLOW_QA_OWNER="$id" MOBILE_FOLLOW_QA_STATE_NAME="$state_name" \
        MOBILE_FOLLOW_QA_PORT="$issuer_port" MOBILE_FOLLOW_QA_WINDOW_MINUTES="${MOBILE_FOLLOW_QA_WINDOW_MINUTES:-60}" \
        SEED_DEMO_ACCOUNTS=false SKIP_DDL_ON_STARTUP=true "$@"
}
cd "$repo/observal-server"
isolated .venv/bin/python "$qa/seed.py" schema > "$run/seed.log" 2>&1
isolated .venv/bin/alembic stamp 044_review_orphan_authors > "$run/migration.log" 2>&1
isolated .venv/bin/alembic upgrade head >> "$run/migration.log" 2>&1
[[ $(docker exec "${id}pg" psql -X -At -U followqa -d followqa -c 'SELECT version_num FROM alembic_version') == 070_mobile_follow_sync_state ]]
# The exact production migration and runtime initialization paths apply and read back
# both source TTLs before the disposable fixture can open synthetic reads.
isolated .venv/bin/python -m services.clickhouse.migrations > "$run/clickhouse.log" 2>&1
isolated .venv/bin/python -c 'import asyncio; from services.clickhouse.schema import init_clickhouse; asyncio.run(init_clickhouse())' >> "$run/clickhouse.log" 2>&1
[[ $(docker exec "${id}pg" psql -X -At -U followqa -d followqa -c \
    "SELECT source_policy_ready AND source_policy_since IS NOT NULL FROM mobile_read_controls WHERE project_id='default'") == t ]] || { echo 'ClickHouse source policy not verified' >&2; exit 1; }
QA_PASSWORD=$(openssl rand -hex 16)
export QA_PASSWORD
isolated .venv/bin/python "$qa/seed.py" fixture >> "$run/seed.log" 2>&1
printf '%s\n' "$QA_PASSWORD" > "$run/password"
# Let the OS assign distinct loopback-only API ports; nginx upstreams share PG/Redis/JWT keys.
for suffix in a b; do
    port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')
    printf '%s\n' "$port" > "$state/port-$suffix"
    isolated .venv/bin/uvicorn app:app --app-dir "$qa" --host 127.0.0.1 --port "$port" --no-access-log > "$run/api-$suffix.log" 2>&1 &
    printf '%s\n' "$!" > "$state/pid-$suffix"
done
isolated .venv/bin/python "$qa/privacy_worker.py" > "$run/privacy-worker.log" 2>&1 &
printf '%s\n' "$!" > "$state/pid-worker"
isolated .venv/bin/python "$qa/projection_worker.py" > "$run/projection-worker.log" 2>&1 &
printf '%s\n' "$!" > "$state/pid-projection"
python3 - "$qa/nginx.conf.template" "$run/nginx.conf" "$(<"$state/port-a")" "$(<"$state/port-b")" "$issuer_port" <<'PY'
import pathlib, sys
text = (pathlib.Path(sys.argv[1]).read_text().replace('__API_A__', sys.argv[3])
        .replace('__API_B__', sys.argv[4]).replace('__ISSUER_PORT__', sys.argv[5]))
pathlib.Path(sys.argv[2]).write_text(text)
PY
for suffix in a b; do
    ready=0
    for _ in {1..40}; do
        if curl -fsS --noproxy '*' "http://127.0.0.1:$(<"$state/port-$suffix")/readyz" >/dev/null; then ready=1; break; fi
        sleep 1
    done
    [[ $ready == 1 ]] || { echo "API $suffix failed; see $run/api-$suffix.log" >&2; exit 1; }
done
docker run -d --name "${id}nginx" --label "observal.followqa.owner=$id" --network host --read-only --tmpfs /var/cache/nginx --tmpfs /var/run \
    -v "$run/nginx.conf:/etc/nginx/nginx.conf:ro" -v "$run/leaf.crt:/qa/leaf.crt:ro" \
    -v "$run/leaf.key:/qa/leaf.key:ro" -v "$web_dist:/web:ro" nginx:alpine >/dev/null
if ! curl -fsS --retry 15 --retry-connrefused --retry-delay 1 --noproxy '*' --cacert "$run/ca.crt" "https://localhost:$issuer_port/readyz" >/dev/null; then
    docker logs "${id}nginx" >&2
    exit 1
fi
# The nginx worker must be able to traverse the asset directory, not just the
# launcher user. Reject a private/unreadable build before spending OAuth quota.
for asset in /login /follow/consent /follow/approve; do
    if ! curl -fsS --noproxy '*' --cacert "$run/ca.crt" "https://localhost:$issuer_port$asset" >/dev/null; then
        echo 'Same-issuer web assets unreadable to nginx; build into a publicly readable isolated directory' >&2
        exit 1
    fi
done
# Full Android QA requires positive, source-verified v1.2 capabilities for
# both identities. No boolean override or manual typed-fact insertion is safe.
# The Pi SDK/extension uploads genuine source through same-issuer HTTPS; the
# running projection worker must publish all three kinds before this launcher
# can return a public CA path to Android.
if ! isolated .venv/bin/python "$qa/populate_source.py" > "$run/source.log" 2>&1; then
    echo 'Isolated Pi source upload/projection failed; refusing QA handoff' >&2
    exit 1
fi
if ! isolated .venv/bin/python "$qa/source_fixture.py" > "$run/source-check.log" 2>&1; then
    echo 'Source-backed v1.2 cohort failed verification; refusing QA handoff' >&2
    exit 1
fi
# Pi source + both-viewer capability proof consumed four localhost login attempts.
# Allow the strict per-IP 5/minute login bucket to drain before the final
# route proof, destructive scratch test, or Android's two-profile sign-in.
# Never relax production auth throttles to make the QA fixture pass.
sleep 65
if ! isolated .venv/bin/python "$qa/verify.py" --routes-only > "$run/route-check.log" 2>&1; then
    echo 'Same-issuer auth/v1.2 capability/browser readiness failed; refusing QA handoff' >&2
    # The cleanup trap deletes the private runtime. Surface only a bounded
    # assertion category, never HTTP bodies, tokens or challenge codes.
    grep -oE '^AssertionError: \([^,]+, [0-9]{3}|^AssertionError: [A-Za-z][A-Za-z 0-9.-]{0,95}' "$run/route-check.log" >&2 || true
    exit 1
fi
started=1
printf 'Isolated issuer: https://localhost:%s\nSession ID: %s\nCA: %s/ca.crt (public cert only; never distribute ca.key)\nLogin: owner@follow-qa.invalid\nPassword: %s/password (0600; do not paste into logs)\nStop: MOBILE_FOLLOW_QA_EXPECT_ID=%s %s/down.sh\n' "$issuer_port" "$id" "$run" "$run" "$id" "$qa"
