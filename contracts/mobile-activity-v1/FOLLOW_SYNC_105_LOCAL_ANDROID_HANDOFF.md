<!-- SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Android: runnable ISOLATED LOCAL follow-sync 1.0.5 reference, not Flare READY

**Backend QA stage pins:** `e90949678df820dd1e3cc5e43b6e7ee043bf2988` (HTTPS reference) plus `730cc559ddbb5249eedea6db5388ca9b5c584287` (privacy poller and this handoff) on `feat/mobile-trace-headlines`; recheck `git rev-parse HEAD` before running. The unregistered production follow routers are included **only** by `tests/integration_mobile/local_follow_qa/app.py`. Same HTTPS issuer for normal `/device`, manual `/follow/approve`, auth and 17 follow endpoints: `https://localhost:18443`. PostgreSQL 18, Redis 7, two distinct FastAPI processes, a separate bounded privacy poller, nginx/static built web UI. Only disposable synthetic test users exist. This is neither a running Flare image nor product-approved sync enablement. QA test artifacts are destroyed on reset; no production/staging trust settings change.

**Reviewed frozen whole-set SHA-256s remain unchanged:** `FOLLOW_SYNC_V105_PROPOSAL.md` `4c6a6d813a3d4e6f5b1465437f67426b4923a10efaf08dfc81429058e48f076e`; `follow-sync-v105-openapi.yaml` `d844f7164afab68b973841397861b7de563fbba69cfc1c5c9500a34b230fb339`; `follow-sync-v105-vectors.json` `40f75853dc07e25d76f7c5b374b7fdb5664576c918700a74e3693ef5f0c0a492`. Accepted v1.2 is untouched. Android reported final source `d2f61f9` and installed separate TEST APK SHA-256 `7de8674d47e6cc47bc0728b4ebf26b35987506100467c7e76ea58a5a8a7c0320`; backend has **not** independently validated its installed build or signer.

## Start, verify and reset (QA host, no Flare)

Read `tests/integration_mobile/local_follow_qa/README.md` for prerequisite installation and guarded commands. In this **isolated backend checkout**:

```bash
cd /home/kaushik/projects/Observal-mobile-trace-headlines
cd web && pnpm install --frozen-lockfile && pnpm build && cd ..
./tests/integration_mobile/local_follow_qa/up.sh
QA_DIR=$(<tests/integration_mobile/local_follow_qa/.runtime/run)
observal-server/.venv/bin/python tests/integration_mobile/local_follow_qa/verify.py
curl --noproxy '*' --cacert "$QA_DIR/ca.crt" -fsS https://localhost:18443/readyz
# Only on an attached Android emulator on this host; check `adb devices` first:
adb reverse tcp:18443 tcp:18443
# After tests: adb reverse --remove tcp:18443
./tests/integration_mobile/local_follow_qa/down.sh
```

`up.sh` prints only the 0600 **local password file path**, never its contents. The newly generated `QA_DIR/ca.crt` is the **public, session-specific CA cert** Android may install into its **QA-only** emulator trust; **NEVER** distribute `ca.key`, `leaf.key`, `jwt/` or the `password` file. The certificate has `DNS:localhost` SAN, expires in two days, and changes on each start. `adb reverse` does not install a CA. Android should build its separate non-debuggable TEST QA variant with `EXPO_PUBLIC_OBSERVAL_ISOLATED_ANDROID_QA=isolated-v3-18443`, configure its QA-only network policy to trust the emulator-installed ephemeral CA **only** for localhost, and prove that invalid/untrusted certificates fail. Do not set `verify=false`, use generic `ignoreHTTPSErrors`, or change production/staging trust. Remove emulator reverse and QA CA trust when finished. Verify `/readyz`, `/login`, `/device`, `/follow/approve` and `/api/v1/mobile-follow-sync/v1/availability` all route through the **same HTTPS origin**; no DNS guesses or LAN hosts.

Disposable credentials: `owner@follow-qa.invalid` and `viewer@follow-qa.invalid` share the generated local-only password in the printed file. Both have separate synthetic read partitions; the source-policy barrier opens for only one hour in the new scratch DB. Use the original device authorize→same-issuer `/device` browser approval→device token flow for mobile credential proof. Browser consent/approval requires the same account and a **recent (≤5 min)** ordinary browser bearer. First obtain explicit consent via `/consent`, then on each authorized phone obtain a challenge via `/write-authorization`; manually open `/follow/approve` and click to approve **one** phone, then redeem `/write-grant` from that phone. This is an isolated synthetic test, **not owner-approved product consent copy or real Follow telemetry access**. `verify.py` exercises real HTTPS auth/device approval, 17-route registration, consent, browser-origin denial, one-use grant and pending removal completed by the local privacy poller without printing secrets; the installed Android/browser click test is still Android-owned.

**Backend evidence and limits:** trusted-CA `curl` and `openssl verify` passed; same issuer login, assets, `/device` and `/follow/approve` returned 200; `verify.py` confirmed real HTTPS original device authorize/confirm/redeem, mobile availability, browser-origin approval, one-use grant, cross-origin 403, replay 401 and pending removal completed by the worker; QA then stopped and removed its certs, keys, processes, containers and listener. Local two-API PostgreSQL/Redis tests validate 17 route schemas but **only 17 of 146 named 1.0.5 vectors have been replayed as real HTTP**, with 129 individually recorded gaps in `tests/integration_mobile/test_follow_vectors_http_postgres_redis.py`. No `adb` binary or attached emulator existed on this backend host at verification; `adb reverse`, Android QA CA import/validation and installed two-device behavior are **Not recorded**, not implied by host TLS tests. If the exact localhost route or trust fails on Android, stop and report its concrete denial, use backend loopback tests only, and do **not** call it an installed-app pass.

Named product/privacy decisions, accountable whole-branch review, 18 excluded-suite human dispositions, candidate-sized PG cost and Flare/Android READY remain **Not recorded / BLOCKED**. Do not enable the production app router, access protected data, publish, merge or roll out based on this local handoff.
