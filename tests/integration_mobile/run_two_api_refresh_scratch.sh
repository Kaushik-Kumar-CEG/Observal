#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
# Opt-in, LOCAL ONLY. Every store/container/secret belongs to this disposable network.
set -Eeuo pipefail
repo=$(cd "$(dirname "$0")/../.." && pwd)
cd "$repo"
id="mobiletwo$RANDOM$RANDOM"; net="${id}net"; keys="${id}keys"; image="local/mobile-two-api:$id"
cleanup() {
  docker rm -fv "${id}apia" "${id}apib" "${id}worker" "${id}pg" "${id}ch" "${id}redis" >/dev/null 2>&1 || true
  docker volume rm "$keys" >/dev/null 2>&1 || true
  docker network rm "$net" >/dev/null 2>&1 || true
}
trap cleanup EXIT
DOCKER_BUILDKIT=1 docker build -q -f docker/Dockerfile.api -t "$image" . >/dev/null
digest=$(docker image inspect "$image" --format '{{.Id}}'); echo "LOCAL_IMAGE_ID=$digest"
docker network create "$net" >/dev/null
docker volume create "$keys" >/dev/null
docker run -d --name "${id}pg" --network "$net" -e POSTGRES_USER=observal -e POSTGRES_PASSWORD=mobile-scratch-only -e POSTGRES_DB=observal postgres:18 >/dev/null
docker run -d --name "${id}ch" --network "$net" -e CLICKHOUSE_USER=observal -e CLICKHOUSE_PASSWORD=mobile-scratch-only -e CLICKHOUSE_DB=observal clickhouse/clickhouse-server:26.6 >/dev/null
docker run -d --name "${id}redis" --network "$net" redis:7-alpine >/dev/null
healthy=0
for _ in $(seq 1 50); do
  if docker exec "${id}pg" pg_isready -q -U observal && docker exec "${id}ch" clickhouse-client --user observal --password mobile-scratch-only -q 'SELECT 1' >/dev/null 2>&1 && docker exec "${id}redis" redis-cli ping | grep -q PONG; then healthy=1; break; fi
  sleep 2
done
[[ "$healthy" -eq 1 ]]
common=(--network "$net" --read-only --tmpfs /tmp:rw,nosuid,noexec,size=64m --mount "type=volume,source=$keys,target=/data" \
  -e "DATABASE_URL=postgresql+asyncpg://observal:mobile-scratch-only@${id}pg:5432/observal" \
  -e "CLICKHOUSE_URL=http://observal:mobile-scratch-only@${id}ch:8123/observal" \
  -e "REDIS_URL=redis://${id}redis:6379" -e JWT_KEY_DIR=/data/keys -e MIGRATION_ARTIFACT_ROOT=/data/migration_artifacts \
  -e SEED_DEMO_ACCOUNTS=false -e SKIP_DDL_ON_STARTUP=true -e "SECRET_KEY=mobile-scratch-${id}-only")
docker run --rm "${common[@]}" "$image" /app/entrypoint.sh > /tmp/mobile-two-api-clock-off.log 2>&1 || { tail -n 20 /tmp/mobile-two-api-clock-off.log; exit 1; }
grep -q MOBILE_PG_COMMIT_CLOCK_UNAVAILABLE /tmp/mobile-two-api-clock-off.log
[[ $(docker exec "${id}pg" psql -X -At -U observal -d observal -c 'SELECT version_num FROM alembic_version') == 069_mobile_publication_clock ]]
echo 'PG_CLOCK_OFF_ORDINARY_INSTALL_SUCCEEDS_MOBILE_UNQUALIFIED=true'
# Disposable fixture only: prove an existing installation with mobile enabled
# cannot proceed to migration on a managed PostgreSQL server lacking the flag.
docker exec "${id}pg" psql -X -q -U observal -d observal -c "INSERT INTO enterprise_config(id,key,value,updated_at) VALUES (gen_random_uuid(),'mobile.auth_enabled','true',clock_timestamp()) ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value" >/dev/null
[[ $(docker exec "${id}pg" psql -X -At -U observal -d observal -c "SELECT value FROM enterprise_config WHERE key='mobile.auth_enabled'") == true ]]
if docker run --rm "${common[@]}" "$image" /app/entrypoint.sh > /tmp/mobile-two-api-enabled-clock-off.log 2>&1; then
  echo 'ERROR: init accepted mobile-enabled off-clock database'; exit 1
fi
grep -q MOBILE_PG_COMMIT_CLOCK_UNAVAILABLE /tmp/mobile-two-api-enabled-clock-off.log
echo 'PG_CLOCK_OFF_MOBILE_ENABLED_INIT_DENIED=true'
docker rm -f "${id}pg" >/dev/null
docker run -d --name "${id}pg" --network "$net" -e POSTGRES_USER=observal -e POSTGRES_PASSWORD=mobile-scratch-only -e POSTGRES_DB=observal postgres:18 postgres -c track_commit_timestamp=on >/dev/null
for _ in $(seq 1 50); do docker exec "${id}pg" pg_isready -q -U observal && break; sleep 1; done
[[ $(docker exec "${id}pg" psql -X -At -U observal -d observal -c 'SHOW track_commit_timestamp') == on ]]
docker run --rm "${common[@]}" "$image" /app/entrypoint.sh > /tmp/mobile-two-api-init.log 2>&1 || { tail -n 30 /tmp/mobile-two-api-init.log; exit 1; }
docker run --rm "${common[@]}" "$image" /app/.venv/bin/python -m services.mobile_boot_preflight > /tmp/mobile-two-api-preflight.json 2>&1 || true
grep -q '"status": "MOBILE_NOT_CONFIGURED"' /tmp/mobile-two-api-preflight.json
grep -q '"pg_commit_clock": "on"' /tmp/mobile-two-api-preflight.json
echo 'READ_ONLY_OPERATOR_DIAGNOSTIC_NOT_CONFIGURED=true'
for suffix in a b; do
  docker run -d --name "${id}api${suffix}" "${common[@]}" "$image" /app/.venv/bin/python -m uvicorn main:app --host 0.0.0.0 --port 8000 --workers 1 >/dev/null
  [[ $(docker inspect "${id}api${suffix}" --format '{{.Image}}') == "$digest" ]]
done
docker run -d --name "${id}worker" "${common[@]}" "$image" /app/.venv/bin/python -c 'import asyncio; asyncio.set_event_loop(asyncio.new_event_loop()); from arq import run_worker; from worker import WorkerSettings; run_worker(WorkerSettings)' >/dev/null
[[ $(docker inspect "${id}worker" --format '{{.Image}}') == "$digest" ]]
echo "PG_HEAD=$(docker exec "${id}pg" psql -X -At -U observal -d observal -c 'SELECT version_num FROM alembic_version')"
docker run --rm -i -e "MOBILE_API_A=${id}apia" -e "MOBILE_API_B=${id}apib" "${common[@]}" "$image" /app/.venv/bin/python - <<'PY'
import asyncio, os, time, uuid
from httpx import AsyncClient, HTTPError
from sqlalchemy import text
from database import async_session
from models.user import User, UserRole
from redis.asyncio import Redis
from services.crypto import init_key_manager
from services.jwt_service import create_access_token, create_refresh_token, decode_refresh_token, decode_access_token, MOBILE_CLIENT_ID

async def main():
    api = ['http://'+os.environ['MOBILE_API_'+letter]+':8000/api/v1' for letter in ('A','B')]
    init_key_manager(key_dir='/data/keys', key_password=None)
    async with AsyncClient(timeout=8, trust_env=False, headers={'user-agent':'observal-mobile-scratch/1'}) as http:
        for site in api:
            for _ in range(160):
                try:
                    ready=await http.get(site.removesuffix('/api/v1')+'/readyz')
                    if ready.status_code==200 and all(ready.json().get(k)=='ok' for k in ('status','postgres','redis','clickhouse')): break
                except HTTPError: pass
                await asyncio.sleep(.3)
            else: raise AssertionError('separate API process not ready')
        print('TWO_SEPARATE_API_CONTAINERS_HEALTHY=true')
        redis=Redis.from_url(os.environ['REDIS_URL'],decode_responses=True)
        try:
            async with async_session() as db:
                assert await db.scalar(text('SELECT count(*) FROM users'))==0
                state=(await db.execute(text("SELECT blocked,source_policy_ready,revocation_pending FROM mobile_read_controls WHERE project_id='default'"))).one()
                assert state.blocked and state.source_policy_ready and not state.revocation_pending
                assert await db.scalar(text("SELECT current_setting('track_commit_timestamp')"))=='on'
                sid=await db.scalar(text('SELECT server_id FROM mobile_server_identity WHERE singleton=true'))
                author=User(id=uuid.uuid4(),name='Disposable Author',email='author@mobile.invalid',username='scratch_author',role=UserRole.super_admin)
                viewer=User(id=uuid.uuid4(),name='Disposable Viewer',email='viewer@mobile.invalid',username='scratch_viewer',role=UserRole.user)
                db.add_all([author,viewer]);await db.commit()
                assert await db.scalar(text('SELECT count(*) FROM users'))==2
                assert await db.scalar(text("SELECT count(*) FROM users WHERE email NOT LIKE '%@mobile.invalid'"))==0
            admin,_=create_access_token(author.id,author.role)
            headers={'authorization':'Bearer '+admin}
            assert (await http.get(api[0]+'/admin/mobile-test/status',headers=headers)).status_code==200
            cohort={'server_id':str(sid),'author_viewer_id':str(author.id),'user_viewer_id':str(viewer.id),
                    'acknowledgement':'isolated-disposable-synthetic-only-v1','expires_in_minutes':10}
            setup=await http.post(api[0]+'/admin/mobile-test/setup',headers=headers,json=cohort)
            assert setup.status_code==200,(setup.status_code,setup.text[:120])
            assert setup.json()['blocked'] is True and setup.json()['configured'] is True
            assert (await http.get(api[1]+'/admin/mobile-test/status',headers=headers)).json()['blocked'] is True
            print('OPERATOR_SETUP_BLOCKED_PERSON_READS=true')
            device='scratch-'+uuid.uuid4().hex
            grant,jti=create_refresh_token(viewer.id,viewer.role,client_id=MOBILE_CLIENT_ID,device_id=device)
            original=decode_refresh_token(grant)
            old='refresh_jti:'+jti
            await redis.setex(old,300,str(viewer.id))
            async def refresh(site, token): return await http.post(site+'/auth/token/refresh',json={'refresh_token':token})
            # Fixture-only reversible pause: authoritative PostgreSQL auth
            # setting changes under a closed read barrier; never a Flare op.
            async with async_session() as db:
                await db.execute(text("UPDATE enterprise_config SET value='false' WHERE key='mobile.auth_enabled'"))
                await db.commit()
            assert (await refresh(api[0],grant)).status_code==503
            assert await redis.get(old)==str(viewer.id)
            async with async_session() as db:
                await db.execute(text("UPDATE enterprise_config SET value='true' WHERE key='mobile.auth_enabled'"))
                await db.commit()
            pair=await asyncio.gather(refresh(api[0],grant),refresh(api[1],grant))
            assert sorted(x.status_code for x in pair)==[200,401],[(x.status_code,x.text[:110]) for x in pair]
            winner=next(x.json() for x in pair if x.status_code==200)
            successor=decode_refresh_token(winner['refresh_token'])
            assert successor['exp']==original['exp'] and successor['sub']==str(viewer.id) and successor['device_id']==device
            assert decode_access_token(winner['access_token'],allow_mobile=True)['exp']<=original['exp']
            assert await redis.get(old) is None and await redis.get('refresh_jti:'+successor['jti'])==str(viewer.id)
            assert 0<await redis.ttl('refresh_jti:'+successor['jti'])<=original['exp']-int(time.time())+1
            assert (await refresh(api[1],grant)).status_code==401
            proof=await http.get(api[1]+'/auth/mobile/credential',headers={'authorization':'Bearer '+winner['access_token']})
            assert proof.status_code==200,(proof.status_code,proof.text[:120])
            assert proof.json()['subject_id']==str(viewer.id) and proof.json()['device_id']==device
            print('PAUSE_REENABLE_JTI_RETAINED=true ATOMIC_WINNERS=1 REPLAY=401 FAMILY_FIXED=true PROOF=200')
            logout=await http.post(api[0]+'/auth/mobile/logout',headers={'authorization':'Bearer '+winner['access_token']},json={'refresh_token':winner['refresh_token']})
            assert logout.status_code==200,(logout.status_code,logout.text[:110])
            dead={'authorization':'Bearer '+winner['access_token']}
            assert (await http.get(api[1]+'/auth/mobile/credential',headers=dead)).status_code==401
            routes=[('GET','/mobile-activity/v1/capabilities',None),
                    ('GET','/mobile-activity/v1/platform/overview?period=1w',None),
                    ('GET',f'/mobile-activity/v1/people/{viewer.id}/summary?scope=user&period=1w',None),
                    ('POST','/mobile-activity/v1/people/summaries',{'subject_ids':[str(viewer.id)],'period':'1w'}),
                    ('GET','/mobile-activity/v1/people?q=scratch',None),
                    ('POST','/mobile-activity/v1/people/resolve',{'subject_ids':[str(viewer.id)]}),
                    ('GET',f'/mobile-activity/v1/people/{viewer.id}/user/components?period=1w&window_anchor=x&revision=x',None),
                    ('GET',f'/mobile-activity/v1/people/{viewer.id}/user/components/mcp/{uuid.uuid4()}?period=1w&window_anchor=x&revision=x',None),
                    ('GET','/mobile-activity/v1/published',None)]
            for method,path,body in routes:
                result=await http.request(method,api[1]+path,headers=dead,json=body)
                assert result.status_code==401,(path,result.status_code)
            assert (await refresh(api[1],winner['refresh_token'])).status_code==401
            print(f'DEVICE_LOGOUT_PREEXPIRY_CREDENTIAL_AND_ALL_{len(routes)}_PROTECTED_ROUTES=401')
            second,key=create_refresh_token(viewer.id,viewer.role,client_id=MOBILE_CLIENT_ID,device_id='second-'+device)
            await redis.setex('refresh_jti:'+key,300,str(viewer.id))
            revoke=await http.post(api[1]+'/admin/mobile-test/revoke',headers=headers)
            assert revoke.status_code==200,(revoke.status_code,revoke.text[:120])
            assert revoke.json()['blocked'] is True and revoke.json()['configured'] is False
            assert (await refresh(api[0],second)).status_code==503
            assert await redis.get('refresh_jti:'+key)==str(viewer.id)
            print('AUDITED_REVOKE_CLOSED=true POSTREVOKE_JTI_UNCONSUMED=true')
        finally: await redis.aclose()
asyncio.run(main())
PY
[[ $(docker inspect "${id}worker" --format '{{.State.Running}}') == true ]]
echo "SAME_IMAGE_ARQ_WORKER_RUNNING=true"
