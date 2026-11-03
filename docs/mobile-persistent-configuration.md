<!-- SPDX-FileCopyrightText: 2026 Kaushik Kumar -->
<!-- SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Persistent, default-closed mobile Following configuration

This replaces the deployment-environment-only controls from candidate `88babc5f`.
It is not production qualification, consent, signing approval or installed acceptance.

## Which controls belong at boot?

| Control | New mechanism | Default / effect |
|---|---|---|
| Following URL registration | Always register the same guarded router set | URL existence grants no access |
| Following capability availability | `mobile.follow_sync_v105_available`, written by the dedicated super-admin API | Missing/false denies new activity |
| Production/new Following activity | Existing owner ACK + operator switch + fresh worker, plus current credential/cohort/privacy checks | OFF; configuration does not open it |
| Synthetic owner-risk permission | Separate audited permit bound to installed server UUID, disposable pair, cohort generation and risk digest | Absent; usable only within the unchanged cohort deadline |
| Synthetic risk activity | Existing separately audited risk-open request, now matching the permit | OFF until explicit matching open |
| Demo seeding policy | `deployment.seed_demo_accounts`, direct DB read under the first-user lock at startup | OFF; any non-demo user always suppresses seeding |
| Database URLs, ES256 key material, process listeners, migrations | Existing boot configuration/preflight | Preserve these; they cannot safely become ordinary live toggles |

`OBSERVAL_FOLLOW_SYNC_V105_ROUTE_INSTALL`,
`OBSERVAL_FOLLOW_SYNTHETIC_RISK_INSTALL` and `SEED_DEMO_ACCOUNTS` are retired.
Leftover values in a preserved Flare environment do not grant authority or seed
accounts. No one-time import turns a legacy environment flag into a DB approval.
Demo credential environment variables remain credentials, not permission to seed.

The earlier assertion that a populated non-demo site necessarily reseeds when
`SEED_DEMO_ACCOUNTS=true` was incorrect: the existing real-user check already
suppressed that. This patch also makes fresh/demo-only startup default-OFF.
Fresh stores use the existing supported first-admin bootstrap (localhost-only);
there is no reset, default administrator creation or SQL enablement shortcut.

## Supported authenticated controls

Use the existing authenticated JSON API client, not host-file writes or generic
enterprise-settings writes for `mobile.*` keys. All mobile settings remain
protected from that generic endpoint.

`GET /api/v1/admin/mobile-test/status` now also reports:
- `installed_server_id`: canonical physical server UUID, including fresh stores;
- `follow_sync_routes_installed`: route shapes are present;
- `follow_sync_available`: persisted capability configuration, not active access;
- `follow_sync_risk_configured`: a permit record exists, not proof it is usable.

`POST /api/v1/admin/mobile-test/configure` requires a normal authenticated
super-admin credential and the exact installed server UUID:

```json
{"server_id":"<installed_server_id>","available":true}
```

Enabling availability requires the real PostgreSQL commit clock, no pending
revocation, absent live qualification and closed Following activity. It writes
only capability configuration and its transactional operator audit. It does not
change mobile authentication, open the read barrier, grant account consent or
approve a device. API/worker restart is not needed for these controls.

For an already configured/open finite disposable cohort, separately arm risk:

```json
{
  "server_id":"<installed_server_id>",
  "available":true,
  "risk_permission":{
    "author_viewer_id":"<selected disposable author>",
    "user_viewer_id":"<selected disposable user>",
    "cohort_generation":123,
    "acknowledgement":"owner-accepted-unreviewed-synthetic-only-v1",
    "risk_acceptance_sha256":"<actual owner-attestation reference digest>"
  }
}
```

The permit requires current disposable principals, exact pair/generation/server,
existing unexpired deadline, ready source policy and a fresh privacy worker.
It never changes the deadline. Then use the existing `/mobile-test/follow-sync`
control with matching risk acknowledgement/digest to open new activity. A review
reference and risk reference remain mutually exclusive; neither is verified as a
signature by this API. Production qualifications are not created here.

Every admission checks fresh DB rows under the shared project/config locks;
Redis/process settings caches and leftover env flags cannot authorize requests.
Normal bearer/Redis revocation, independent website actor/action proof, account
consent, per-device edit approval, exact subjects and owner-generation fences
remain unchanged. No permission here fabricates phone/browser evidence.

Disabling availability with `available:false` also sets the operator switch OFF.
It preserves existing bounded ACK/permit provenance so original-ID same-owner
status recovery can continue through its independent worker, cohort, expiry and
privacy fences. Owner withdrawal/erasure receipt handling remains independent of
new-activity availability. This is not permission to replay an operation POST.
The existing audited cohort revoke/setup clears risk permission and authority;
revocation/expiry makes the old permit unusable. Revoke and verify early rather
than relying on expiry, then disable availability before ending supervision.

## Upgrade / deployment without Flare env editing

1. Review/publish the exact new source revision to a pinned fork branch. Keep
   fork main unchanged and retain the APK's existing source/signer pins.
2. On the **existing** `mobile-app` Flare site, select that full Commit SHA and
   Redeploy with auto-update/auto-wipe OFF. No environment-variable editing is
   required. Do not recreate the site, run Terraform apply, wipe/reseed or replace
   any credentials/volumes. This source's supported Compose initializer must run
   before API/worker and must build all application services from that revision.
3. Existing versioned PG080/081/082 uses `alembic upgrade head` through
   **`083_mobile_persistent_config`**. Fresh bootstrap remains the existing fresh
   initializer path. No stamp against a populated database; no reset or history
   restore. CH migration/source-policy initialization remains unchanged.
4. Verify actual deployed init/API/worker/web/Pi pins, physical PG083 constraints,
   fresh worker, persistent admin/data/signing identity and closed defaults.
   Source selection alone is NOT proof this deployed path ran correctly.
5. Only after readiness, use the supported authenticated controls above. Normal
   Following activity and synthetic risk remain OFF after deployment. No test
   cohort, deadline or consent is automatically created.

Drain/close old activity and revoke any old disposable cohort before upgrading a
mixed-version installation. PG083 never imports an old risk ACK/environment flag
as a new permit. Missing permission may deny old risk status; preserve history
and do not infer an operation's result or replay it.

PG083 inserts missing OFF configuration rows only, preserving all existing users,
settings, identity, source records and prior review/risk/erasure audit. It expands
validated audit actions with `follow_cfg_open`, `follow_cfg_close` and
`follow_risk_arm`, preserving the existing varchar widths and distinct authority
constraint. Boot checks the actual constraints, not just an Alembic stamp.
An exercised PG083 configuration-audit downgrade is refused. Retain PG083 and
close/revoke through supported controls. A reviewed PG083-compatible CLOSED
bridge must accompany this candidate before deployment; it denies new activity
regardless of persisted settings but keeps fenced owner recovery and admin
close/revoke. An old PG082-only runtime/rollback image
will fail its head check and is not a compatible rollback. Never overwrite later
privacy history with an older backup.

## Verification scope

Focused tests cover closed defaults despite old env values, explicit availability,
separate exact-cohort risk permission, wrong identity/pair/generation, missing
worker/clock, expiry, mixed attestation rejection, no commit on audit failure,
recovery/withdrawal boundaries and retained non-demo users. Normal HTTP integration
uses real JWT/Redis/PostgreSQL, durable control read-back and refused downgrade;
only the secondary external ClickHouse event sink is stubbed. Populated migration
rehearsals restore a real dump and verify user digest/defaults plus actual-image
boot. These remain local controlled evidence, not a Flare deployment, installed
phone acceptance, independent human security review or production approval.
