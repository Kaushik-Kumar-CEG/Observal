<!-- SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Operator-only read-only Flare candidate receipt — NOT Android READY

**Scope:** `mobile-rc-062.observal.io` only. Do not query or redeploy `dev.observal.io` or the persistent mobile-test trial. Never send passwords, tokens, env files, complete container logs, user email, raw source or ClickHouse traces. Public `/readyz` is not an image, account, store, schema or barrier receipt. As of 2026-10-19 08:27 UTC the public candidate still returned `initialized=true`; the owner identifies the account as a team member, but its actual role/provenance have not been independently verified.

## 1. Find the *actual* candidate node using owner-authorized controls

In Flare's deployment view, read its immutable candidate deployment/instance reference, source pin, cloud account, AWS region and target EC2 instance ID. Cross-check the source pin with the owner record `2a8153b1689d32f7a011b6826905563160bbd8f7`; do not infer an instance from DNS alone (a proxy can terminate TLS elsewhere). If it is not AWS EC2/SSM, use Flare's **candidate-only** authorized console/shell and skip the AWS commands. Do not change anything to obtain access. If EC2/SSM is supported, from an AWS CLI v2 environment authorized for *that account/region*, after replacing placeholders:

```sh
REGION='<Flare-provided-region>'
INSTANCE_ID='<Flare-provided-i-...>'
aws sts get-caller-identity --query '{Account:Account,Arn:Arn}'
aws ec2 describe-instances --region "$REGION" --instance-ids "$INSTANCE_ID" \
  --query 'Reservations[].Instances[].{Id:InstanceId,State:State.Name,Type:InstanceType,PrivateIP:PrivateIpAddress,PublicIP:PublicIpAddress}'
aws ssm describe-instance-information --region "$REGION" \
  --filters "Key=InstanceIds,Values=$INSTANCE_ID" \
  --query 'InstanceInformationList[].{Id:InstanceId,PingStatus:PingStatus,Platform:PlatformName}'
aws ssm start-session --region "$REGION" --target "$INSTANCE_ID" \
  --reason 'candidate-only-mobile-read-only-preflight'
```

Stop if the account/instance does not match Flare's candidate or SSM is not Online; **do not substitute a dev node**. CLI `start-session` needs the Session Manager plugin; an authorized AWS Console Session Manager shell is an alternative. SSM gives a shell, **not** proof of authorization for writes. Use only read operations below; no `docker compose up`, `exec -it` bootstrap, SQL updates, or secrets inspection yet.

## 2. Within the verified candidate node, privately inventory and redact

Turn tracing off (`set +x`). Locate *that node's* Docker Compose project and match each container's Compose project label; avoid combining another stack's containers. The repository's single-node compose uses services `observal-init`, `observal-api`, `observal-worker`, `observal-db`, `observal-clickhouse`, `observal-redis`, but Flare may name them differently: confirm from its deployment manifest instead of assuming those names. Read-only examples once each role's full container ID is verified (`INIT`, `API`, `WORKER`, `DB`, `CH`, `REDIS` are shell-local placeholders):

```sh
docker ps -a --format '{{.ID}} {{.Names}} {{.Image}} {{.Status}} {{.Label "com.docker.compose.project"}} {{.Label "com.docker.compose.service"}}'
for name in "$INIT" "$API" "$WORKER" "$DB" "$CH" "$REDIS"; do
  docker inspect "$name" --format '{{.Name}} image_id={{.Image}} state={{.State.Status}} exit={{.State.ExitCode}}'
done
for name in "$INIT" "$API" "$WORKER"; do
  docker inspect "$name" --format '{{.Name}} revision={{index .Config.Labels "org.opencontainers.image.revision"}} source={{index .Config.Labels "observal.source"}}'
done
# If neither image label exists, report "label absent"; a host checkout or tag is NOT proof of image source.
# Compare image IDs of init/API/every API replica/worker; require completed-zero init and running worker.
docker logs "$WORKER" --since 15m 2>/dev/null | grep -c 'run_mobile_projection_queue' || true
```

Do not print `.Config.Env`, volumes' file contents, `docker compose config` (can expand secrets), or unredacted logs. Privately compare the DB/ClickHouse/Redis containers, mounts and endpoint identities with Flare's candidate manifest and with dev's documented inventory (if authorized); report only **distinct/not-proved**, not private connection strings. An image ID (`sha256:...`) is an immutable *local* image identity; an external registry digest/source revision label must be recorded separately if available.

On the candidate DB container use **SELECT only**. The following expands DB username/name from that container's own environment without printing password values; change the command only if Flare's actual database service differs:

```sh
docker exec -i "$DB" sh -c 'exec psql -X -A -t -U "$POSTGRES_USER" -d "$POSTGRES_DB"' <<'SQL'
SELECT version_num FROM alembic_version;
SELECT server_id FROM mobile_server_identity WHERE singleton=true;
SELECT blocked,generation FROM mobile_read_controls WHERE project_id='default';
SELECT count(*) FROM users;
SELECT role,is_demo,auth_provider,count(*) FROM users GROUP BY role,is_demo,auth_provider ORDER BY role,is_demo,auth_provider;
SELECT count(*) FROM mobile_operator_audit;
SELECT key,CASE WHEN value IN ('true','false') THEN value ELSE 'set-other' END FROM enterprise_config WHERE key IN ('mobile.auth_enabled','mobile.synthetic_test_enabled','trace_headlines') ORDER BY key;
SQL
```

If Flare does not run that PostgreSQL container or the image lacks `psql`, use its documented read-only DB console to execute the same seven SELECT statements. **Do not improvise a mutation.** Compare the account privately with the known team member using an existing authorized admin view or a private account ID; the shared receipt contains only role, demo flag, provider, creation timeframe and a salted/hashed account reference. Verify whether an authorized non-demo super-admin already exists. A nonempty DB must **never** use `python -m services.first_admin`; an ordinary admin cannot create a higher-role Author.

For old 062, check `mobile_read_controls.blocked=true`, `generation`, `trace_headlines=false`, mobile auth and synthetic settings disabled, mobile operator audit row count and init exit; 064/065 fields do **not** exist yet. Read-only ClickHouse migration ledger, **only after privately confirming its actual database name and authentication**, is `SELECT version,applied_at FROM clickhouse_schema_migrations ORDER BY version` (database from the candidate manifest). Redact any internal endpoint/credential, and confirm the worker's current projection job count without emitting its raw log. Do not treat absence of an audit row as proof of account provenance.

**Minimal redacted receipt to return:** UTC time; Flare deployment ID/AWS account and candidate instance ID (may hash the account/instance ID in a public report while retaining private comparison); verified hostname binding; Compose project; actual image ID/source label for *each* init/API replica/worker and init exit/worker running; PostgreSQL head; ClickHouse migration head/count; distinct-store confirmation or `unproven`; server ID; blocked/generation; mobile auth/synthetic/trace switches; role/is_demo/auth_provider grouped counts and team-member provenance assertion; any unexpected account/privilege. No credential, email, env or raw traces.

## 3. Deployment decision after the receipt

- If the existing account is a verified authorized non-demo super-admin, it can create new reserved-domain disposable Author/User and separate reviewer through supported APIs **after** a reviewed upgrade and preflight. Never use a real team member as synthetic Author. If it is admin/reviewer/user only and no authorized super-admin exists, the **nonempty** instance cannot run the empty-install provisioner: require an owner-approved **fresh isolated candidate** with disabled demo seed and a private local-TTY first-admin provisioning step, or another documented supported authority path. No SQL promotion.
- If isolation, provenance, or a recoverable migration path is unproven, **do not deploy over this instance**. Prepare a fresh isolated candidate with new stores or an approved backup/restore-tested route. Do not silently repoint the app or change source image while an Android test is open.
- For **closed-gate diagnostic-only deployment** after explicit owner authorization *and* a safe instance-bound receipt, the exact reviewed 066 runtime source is **`791b1af0f7bcc096ab108b16bba95570267ce62c`**, migration head **`066_mobile_scope_retention_clock`**. This is a source/test commit, **not** a claimed Flare image or deployment. Build/publish one immutable image from that commit through Flare's documented commit-pin control, not a moving branch tag. Record the *new running* init/API(each replica)/worker image IDs and source labels; the old local-only 065 image `sha256:9652076ceceea158237e277c1967871e4378822763852b52852a94dc14f74e84` is **not** a 066 or Flare digest. Confirm init exit zero and Alembic 066, ClickHouse ledger, worker projection process, unchanged `mobile_server_identity.server_id` if upgrading, and **`blocked=true,revocation_pending=false,synthetic_expires_at=NULL`**, mobile auth/synthetic/trace switches off, user inventory unchanged, CA-verified same-origin `/readyz`, `/login`, `/device`, authenticated `mobile-test-status` with the supported operator credential, and anonymous named-route 401. If any pin changes, previous public 062 evidence is invalid. The typed child cursor repair is tested only in isolated 066 PostgreSQL, **not** on Flare. Do not create the cohort or issue Android READY until authorized viewers, real invoked typed facts, scoped denial, generation, deadline and cleanup owner are independently verified; Android acceptance and the 500 ms product gate remain separate.

**Sources:** repository `infra/terraform/aws-ec2/README.md` (SSM host access); AWS CLI command reference `/websites/aws_amazon_cli` (EC2 `describe-instances`, SSM `describe-instance-information` and `start-session`).
