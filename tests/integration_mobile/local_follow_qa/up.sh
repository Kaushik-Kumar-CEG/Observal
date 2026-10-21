#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Kaushik Kumar <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
set -Eeuo pipefail
umask 077
qa=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$qa/../../.." && pwd)
state="$qa/.runtime"
[[ ! -e "$state" && ! -L "$state" ]] || { echo 'QA already running or stale state; run down.sh first' >&2; exit 1; }
[[ -x "$repo/observal-server/.venv/bin/uvicorn" && -x "$repo/observal-server/.venv/bin/alembic" ]] || { echo 'Install server dependencies: cd observal-server && uv sync' >&2; exit 1; }
[[ -s "$repo/web/dist/index.html" ]] || { echo 'Build current UI: cd web && pnpm install --frozen-lockfile && pnpm build' >&2; exit 1; }
[[ ! -e "$repo/observal-server/.env" && ! -L "$repo/observal-server/.env" ]] || { echo 'Refusing to load server .env; use a clean isolated checkout' >&2; exit 1; }
for binary in docker openssl curl python3; do command -v "$binary" >/dev/null || { echo "missing $binary" >&2; exit 1; }; done
docker info >/dev/null
# Reject ANY preexisting listener on this port, including IPv6 (no listener is replaced).
python3 - <<'PY'
import socket
for family, address in ((socket.AF_INET, ('0.0.0.0', 18443)), (socket.AF_INET6, ('::', 18443))):
    with socket.socket(family) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # TIME_WAIT is not a listener
        if family == socket.AF_INET6: sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        sock.bind(address)
PY
mkdir -m 700 "$state"
cleanup() { "$qa/down.sh" >/dev/null || true; }
started=0
trap 'if [[ $started == 0 ]]; then cleanup; fi' EXIT
id="followqa$(python3 -c 'import secrets; print(secrets.token_hex(5))')"
printf '%s\n' "$id" > "$state/id"
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
docker run -d --name "${id}pg" -p 127.0.0.1::5432 -e POSTGRES_USER=followqa \
    -e POSTGRES_PASSWORD=disposable-follow-qa -e POSTGRES_DB=followqa postgres:18 \
    postgres -c track_commit_timestamp=on >/dev/null
docker run -d --name "${id}redis" -p 127.0.0.1::6379 redis:7-alpine >/dev/null
pgport=$(docker port "${id}pg" 5432/tcp | awk -F: '{print $NF}')
redisport=$(docker port "${id}redis" 6379/tcp | awk -F: '{print $NF}')
for _ in {1..60}; do docker exec "${id}pg" pg_isready -q -U followqa && docker exec "${id}redis" redis-cli ping 2>/dev/null | grep -q PONG && break; sleep 1; done
docker exec "${id}pg" pg_isready -q -U followqa
docker exec "${id}redis" redis-cli ping | grep -q PONG
export DATABASE_URL="postgresql+asyncpg://followqa:disposable-follow-qa@127.0.0.1:$pgport/followqa"
export REDIS_URL="redis://127.0.0.1:$redisport/0"
export SECRET_KEY="$(openssl rand -hex 32)" JWT_KEY_DIR="$run/jwt" SEED_DEMO_ACCOUNTS=false SKIP_DDL_ON_STARTUP=true
# Neither the parent shell nor a server .env may inject production service URLs or tokens.
isolated() {
    env -i PATH="$PATH" HOME="$HOME" LANG="${LANG:-C.UTF-8}" PYTHONPATH="$PWD" DATABASE_URL="$DATABASE_URL" \
        REDIS_URL="$REDIS_URL" CLICKHOUSE_URL=http://127.0.0.1:9/unused \
        SECRET_KEY="$SECRET_KEY" JWT_KEY_DIR="$JWT_KEY_DIR" QA_PASSWORD="${QA_PASSWORD:-}" \
        MOBILE_FOLLOW_LOCAL_QA=1 SEED_DEMO_ACCOUNTS=false SKIP_DDL_ON_STARTUP=true "$@"
}
cd "$repo/observal-server"
isolated .venv/bin/python "$qa/seed.py" schema > "$run/seed.log" 2>&1
isolated .venv/bin/alembic stamp 044_review_orphan_authors > "$run/migration.log" 2>&1
isolated .venv/bin/alembic upgrade head >> "$run/migration.log" 2>&1
[[ $(docker exec "${id}pg" psql -X -At -U followqa -d followqa -c 'SELECT version_num FROM alembic_version') == 070_mobile_follow_sync_state ]]
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
python3 - "$qa/nginx.conf.template" "$run/nginx.conf" "$(<"$state/port-a")" "$(<"$state/port-b")" <<'PY'
import pathlib, sys
text = pathlib.Path(sys.argv[1]).read_text().replace('__API_A__', sys.argv[3]).replace('__API_B__', sys.argv[4])
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
docker run -d --name "${id}nginx" --network host --read-only --tmpfs /var/cache/nginx --tmpfs /var/run \
    -v "$run/nginx.conf:/etc/nginx/nginx.conf:ro" -v "$run/leaf.crt:/qa/leaf.crt:ro" \
    -v "$run/leaf.key:/qa/leaf.key:ro" -v "$repo/web/dist:/web:ro" nginx:alpine >/dev/null
if ! curl -fsS --retry 15 --retry-connrefused --retry-delay 1 --noproxy '*' --cacert "$run/ca.crt" https://localhost:18443/readyz >/dev/null; then
    docker logs "${id}nginx" >&2
    exit 1
fi
started=1
printf 'Isolated issuer: https://localhost:18443\nCA: %s/ca.crt (public cert only; never distribute ca.key)\nLogin: owner@follow-qa.invalid\nPassword: %s/password (0600; do not paste into logs)\nStop: %s/down.sh\n' "$run" "$run" "$qa"
