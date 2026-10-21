<!-- SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Local follow-sync QA only

This disposable fixture **does not enable production follow-sync**. `app.py` explicitly registers the 17 otherwise-unregistered endpoints alongside the existing auth/device/config routes, for two independent loopback API processes and a separate bounded restartable privacy worker behind one local HTTPS nginx issuer. PostgreSQL 18 and Redis run in newly named disposable containers on random loopback ports, with no shared volumes or production/Flare access. Do not run on a shared or remotely reachable host. The synthetic read barrier opens **only in the disposable database** for one disposable owner for one hour; restart from scratch after expiration. No protected accounts or fixtures are read.

Prerequisites: Docker daemon, OpenSSL, curl, Python 3, `observal-server/.venv` installed from the server lockfile (`cd observal-server && uv sync`), web built from this checkout (`cd web && pnpm install --frozen-lockfile && pnpm build`). Docker images `postgres:18`, `redis:7-alpine`, `nginx:alpine` must be available; install/pull in advance if offline. The script refuses `observal-server/.env` and scrubs inherited environment for all server commands (including any production URLs/tokens); use a clean checkout. Never run the script with sudo. Check `git status` before and after; no Android repository is touched.

```bash
./tests/integration_mobile/local_follow_qa/up.sh
# The command prints the local CA certificate path, disposable login, and 0600 password file path.
# Set QA_DIR to the printed /tmp/observal-follow-qa.* directory, without exposing ca.key.
QA_DIR=$(<tests/integration_mobile/local_follow_qa/.runtime/run)
observal-server/.venv/bin/python tests/integration_mobile/local_follow_qa/verify.py
curl --noproxy '*' --cacert "$QA_DIR/ca.crt" -fsS https://localhost:18443/readyz
curl --noproxy '*' --cacert "$QA_DIR/ca.crt" -fsS https://localhost:18443/login >/dev/null
curl --noproxy '*' --cacert "$QA_DIR/ca.crt" -fsS https://localhost:18443/device >/dev/null
curl --noproxy '*' --cacert "$QA_DIR/ca.crt" -fsS https://localhost:18443/follow/approve >/dev/null
curl --noproxy '*' --cacert "$QA_DIR/ca.crt" -sS -o /dev/null -w '%{http_code}\n' -H 'content-type: application/json' -d '{"client_id":"observal-mobile"}' https://localhost:18443/api/v1/auth/device/authorize
curl --noproxy '*' --cacert "$QA_DIR/ca.crt" -sS -o /dev/null -w '%{http_code}\n' https://localhost:18443/api/v1/mobile-follow-sync/v1/availability # 401 without phone credentials
./tests/integration_mobile/local_follow_qa/down.sh
# Confirm no listener on 18443, no followqa* containers, and temp directory removed.
```

For a **real browser approval**: on the same host visit `https://localhost:18443/login` in a browser which trusts **only the public disposable CA certificate** for this QA session; sign in as `owner@follow-qa.invalid` with the local password file. Pair through the original `/api/v1/auth/device/authorize` → browser `/device` confirmation → `/api/v1/auth/device/token` (one-use). Then use the resulting **mobile** token to call availability, establish consent using the actual follow API, request `write-authorization`, and open its `verification_uri` in the signed-in browser. `/follow/approve` sends the original signed-in browser bearer plus same-origin header to `write-approval`. Redeem `write-grant` with the phone token. Never paste access tokens, codes, or passwords into issue reports or shell history. Auth is the real server auth/device flow, not an offline mock. The SPA relies on `/api/v1/config/public` and the original auth endpoints. `verify.py` tests the approval API with a real desktop login token and Origin over TLS, plus cross-origin denial, grant replay and pending removal completed by the separate privacy worker; it does **not** exercise clicks in a real browser or claim installed-app proof. Interactive browser UI approval remains manual.

**Emulator only, optional** (requires an attached Android emulator and a separately prepared Android QA build; nothing here installs one): `adb reverse tcp:18443 tcp:18443`. In the **Android QA build only**, trust this session's public `ca.crt` for `localhost`; never put the CA private key on Android, never trust it in a production build or modify a production trust store. The leaf has a localhost DNS SAN. Remove reverse with `adb reverse --remove tcp:18443` before teardown. Browser on a different host cannot reach this loopback issuer. If no emulator/build is available, no Android installed-app proof is claimed.

`down.sh` removes only containers with its recorded random prefix, verified API/worker process IDs, and its own `/tmp/observal-follow-qa.*` runtime directory (including the host-only CA private key, leaf key, JWT signing keys, and password), then checks that 18443 no longer answers. It does not change any system/browser/Android trust setting: remove any manually installed CA yourself. Failure before startup completion automatically invokes teardown. Do not distribute the CA key or runtime directory. Use the CA file only for the current session; it expires in two days and changes at every start.
