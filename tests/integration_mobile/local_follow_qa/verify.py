# SPDX-FileCopyrightText: 2026 Kaushik Kumar <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Local-only actual HTTP checks. Never prints tokens, codes, password, or CA key."""

import asyncio
import os
import re
import ssl
import sys
import uuid
from pathlib import Path

import httpx


async def main():
    qa = Path(__file__).resolve().parent
    state_name = os.environ.get("MOBILE_FOLLOW_QA_STATE_NAME", ".runtime")
    issuer_port = int(os.environ.get("MOBILE_FOLLOW_QA_PORT", "18443"))
    assert (
        (state_name == ".runtime" and issuer_port == 18443)
        or (re.fullmatch(r"\.runtime-scratch-[0-9a-f]{6,12}", state_name) and issuer_port == 18444)
        or (re.fullmatch(r"\.runtime-android-[0-9a-f]{6,12}", state_name) and issuer_port == 18446)
        or (re.fullmatch(r"\.runtime-android-next-[0-9a-f]{6,12}", state_name) and issuer_port == 18448)
        or (re.fullmatch(r"\.runtime-android-diagnostic-[0-9a-f]{6,12}", state_name) and issuer_port == 18449)
    ), "refusing unrelated QA state or port"
    state = qa / state_name
    assert (state / "issuer-port").read_text().strip() == str(issuer_port)
    runtime = Path((state / "run").read_text().strip())
    origin = f"https://localhost:{issuer_port}"
    tls = ssl.create_default_context(cafile=str(runtime / "ca.crt"))
    async with httpx.AsyncClient(verify=tls, base_url=origin, timeout=15, trust_env=False) as client:
        for path in ("/readyz", "/login", "/device", "/follow/approve", "/follow/consent"):
            r = await client.get(path)
            assert r.status_code == 200, (path, r.status_code)
            if path != "/readyz":
                assert '<div id="root"></div>' in r.text
                scripts = re.findall(r'<script[^>]+src="(/[^"]+\.js)"', r.text)
                assert scripts, path
                js = await client.get(scripts[0])
                assert js.status_code == 200 and "javascript" in js.headers.get("content-type", "")
        print("TRUSTED_TLS_SPA_LOGIN_DEVICE_FOLLOW_APPROVE_CONSENT_ASSETS=200")
        ports = [(state / f"port-{suffix}").read_text().strip() for suffix in ("a", "b")]
        for port in ports:
            async with httpx.AsyncClient(trust_env=False) as api:
                assert (await api.get(f"http://127.0.0.1:{port}/readyz")).status_code == 200
        print("TWO_SEPARATE_API_PROCESSES_READY=200")
        path = "/api/v1/mobile-follow-sync/v1"
        assert (await client.get(path + "/availability")).status_code == 401
        password = (runtime / "password").read_text().strip()
        login = await client.post("/api/v1/auth/login", json={"email": "owner@follow-qa.invalid", "password": password})
        assert login.status_code == 200, ("login", login.status_code, login.text[:200])
        desktop = {"Authorization": "Bearer " + login.json()["access_token"], "Origin": origin}
        async with (
            httpx.AsyncClient(base_url=f"http://127.0.0.1:{ports[0]}", trust_env=False) as first,
            httpx.AsyncClient(base_url=f"http://127.0.0.1:{ports[1]}", trust_env=False) as second,
        ):
            auth = await first.post("/api/v1/auth/device/authorize", json={"client_id": "observal-mobile"})
            assert auth.status_code == 200, ("device authorize", auth.status_code, auth.text[:200])
            challenge = auth.json()
            assert challenge["verification_origins"] == [origin]
            assert challenge["verification_uri_complete"].startswith(origin + "/device?")
            confirmed = await second.post(
                "/api/v1/auth/device/confirm", headers=desktop, json={"user_code": challenge["user_code"]}
            )
            assert confirmed.status_code == 200, ("device confirm", confirmed.status_code, confirmed.text[:200])
            redeem = await first.post(
                "/api/v1/auth/device/token",
                json={
                    "device_code": challenge["device_code"],
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                },
            )
            assert redeem.status_code == 200, ("device token", redeem.status_code, redeem.text[:200])
        https_challenge = await client.post("/api/v1/auth/device/authorize", json={"client_id": "observal-mobile"})
        assert https_challenge.status_code == 200
        assert https_challenge.json()["verification_origins"] == [origin]
        assert https_challenge.json()["verification_uri_complete"].startswith(origin + "/device?")
        https_confirm = await client.post(
            "/api/v1/auth/device/confirm",
            headers=desktop,
            json={"user_code": https_challenge.json()["user_code"]},
        )
        assert https_confirm.status_code == 200, ("HTTPS device confirm", https_confirm.status_code)
        https_redeem = await client.post(
            "/api/v1/auth/device/token",
            json={
                "device_code": https_challenge.json()["device_code"],
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            },
        )
        assert https_redeem.status_code == 200, ("HTTPS device redeem", https_redeem.status_code)
        phone = {"Authorization": "Bearer " + https_redeem.json()["access_token"]}
        credential = await client.get("/api/v1/auth/mobile/credential", headers=phone)
        assert credential.status_code == 200, ("mobile credential", credential.status_code)
        print("REAL_PASSWORD_LOGIN_DEVICE_AUTHORIZE_CONFIRM_REDEEM_PROOF=200")
        capabilities = await client.get("/api/v1/mobile-activity/v1/capabilities", headers=phone)
        assert capabilities.status_code == 200, ("v1.2 mobile capabilities", capabilities.status_code)
        assert capabilities.json()["viewer_id"] and capabilities.json()["server_id"]
        assert (await client.get("/api/v1/mobile-activity/v1/capabilities")).status_code == 401
        print(
            "ACCEPTED_V12_SIGNED_IN_CAPABILITIES=200; ANONYMOUS=401; "
            f"SYNTHETIC_TEST_COHORT={capabilities.json()['synthetic_test_cohort']}; "
            f"SUPPORTED_KINDS={len(capabilities.json()['supported_kinds'])}"
        )
        if "--routes-only" in sys.argv:
            assert capabilities.json()["synthetic_test_cohort"] is True, "Android would reject trace capability"
            assert capabilities.json()["supported_kinds"] == [
                "mcp_calls",
                "confirmed_skill_loads",
                "recorded_hook_runs",
            ], "v1.2 capability lacks verified three-kind source"
            # Authorization challenge creates only short-lived OAuth state. Do
            # not change owner consent, follow grants or removals on Android's
            # final shared session.
            return
        available = await client.get(path + "/availability", headers=phone)
        assert available.status_code == 200, ("availability", available.status_code, available.text[:200])
        generation = available.json()["owner_generation"]
        consent = await client.post(
            path + "/consent",
            headers=desktop,
            json={"consent": True, "consent_id": str(uuid.uuid4()), "owner_generation": generation},
        )
        assert consent.status_code == 200, ("consent", consent.status_code, consent.text[:200])
        start = await client.post(path + "/write-authorization", headers=phone)
        assert start.status_code == 200, ("write-authorization", start.status_code, start.text[:200])
        assert start.json()["verification_uri"].startswith(origin + "/follow/approve?code=")
        denied = await client.post(
            path + "/write-approval",
            headers={"Authorization": desktop["Authorization"], "Origin": "https://wrong.invalid"},
            json={"user_code": start.json()["user_code"], "approve": True},
        )
        assert denied.status_code == 403, ("cross-origin rejection", denied.status_code)
        approval = await client.post(
            path + "/write-approval", headers=desktop, json={"user_code": start.json()["user_code"], "approve": True}
        )
        assert approval.status_code == 200, ("write-approval", approval.status_code, approval.text[:200])
        grant = await client.post(path + "/write-grant", headers=phone)
        assert grant.status_code == 200, ("write-grant", grant.status_code, grant.text[:200])
        replay = await client.post(path + "/write-grant", headers=phone)
        assert replay.status_code == 401, ("one-use grant replay", replay.status_code)
        edit = {"Authorization": "Bearer " + grant.json()["access_token"]}
        prepared = await client.post(path + "/removals/prepare", headers=edit)
        assert prepared.status_code == 200, ("removal prepare", prepared.status_code)
        removal = await client.post(
            path + "/removals",
            headers=edit,
            json={
                "nonce": prepared.json()["nonce"],
                "confirm": True,
                "owner_generation": consent.json()["owner_generation"],
            },
        )
        assert removal.status_code == 202, ("removal pending", removal.status_code)
        complete = False
        for _ in range(30):
            status = await client.get(path + "/removals/" + removal.json()["removal_id"], headers=phone)
            assert status.status_code == 200, ("removal status", status.status_code)
            if status.json()["state"] == "completed":
                complete = True
                break
            await asyncio.sleep(1)
        assert complete, "local privacy worker did not durably complete removal within 30 seconds"
        print("FOLLOW_AVAILABILITY_CONSENT_BROWSER_ORIGIN_APPROVAL_ONE_USE_GRANT=200; CROSS_ORIGIN=403; REPLAY=401")
        print("DURABLE_REMOVAL_PENDING_TO_WORKER_COMPLETED=202_TO_200")


if __name__ == "__main__":
    asyncio.run(main())
