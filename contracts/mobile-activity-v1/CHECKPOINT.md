<!-- SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Durable backend/mobile checkpoint — 2026-10-13

**Status: INCOMPLETE. No mobile-activity endpoint, least-privilege phone credential or qualified evidence pipeline is implemented. No gate is verified complete. Do not ship a live phone login or display live component/platform totals.** This file is a continuation marker, not approval for a PR/merge/deployment.

## Pushed branches (all based on freshly fetched upstream `ca47a952`, independent)

| Branch | Commit | Scope |
| --- | --- | --- |
| `feat/mobile-activity-contract` | `e8e89518` | Proposed OpenAPI contract + synthetic fixtures; not a shipped API. |
| `fix/mobile-snapshot-isolation` | `1f52ae02` | Snapshot POST/GET/diff scoped by uploader and project; legacy Insights significant content path disabled. |
| `fix/mobile-graphql-subscriptions` | `e0811603` | Session global/item channels require trace-admin permission rechecked per event. Global/listing-only review subscriptions fail closed until event payload can be reauthorized; review-ID channel continues per-event checks. |
| `fix/mobile-ingest-log-privacy` | `c057ee92` | Malformed transcript bytes/exception text, device verification codes and device-flow emails no longer logged. |
| `fix/mobile-auth-grant-races` | `2719adcb` | Atomic refresh GETDEL and device approval/redemption Lua transitions; not mobile scopes. |

Contract SHA-256: OpenAPI `7b66beee1f49bbfd0e908cbd8a1350c082ac9ab021564702e632272e6875cdd1`; fixtures `06a8e763682a21553dff8f1b1de0074bd91ca6ecac75ef657b0992a6c1a971f4` (pre-checkpoint hashes unchanged). Shared proposed platform overview amendment is in the mobile repo's currently untracked `IMPLEMENTATION_PLAN.md`; mobile handoff in `BACKEND_CONTRACT_HANDOFF.md`. **Mobile agent must confirm placement and pin hash**. No safe inference of maintainer permission or sender cohort from repository source. PR #1779 head `4d340f96` fetched and compared; its merge-base against current main is `3bc173c6` and it is not a drop-in cherry-pick.

## Exact evidence so far

- Contract YAML parsed and 8 synthetic fixture cases validated; `git diff --check`; repository pre-commit hooks passed.
- Snapshot security: `uv run pytest -q tests/test_layer_snapshot_routes.py tests/test_layer_snapshot_security.py` from `observal-server/` with server deps: **41 passed**; ruff clean. Adversarial check: same hash, independent uploads, owner GET and denied non-owner GET/diff. These are mocks, not real ClickHouse validation. Insights content disable is a temporary security regression requiring maintainer sign-off/replacement with identity-bound reporting.
- GraphQL: focused `tests/test_graphql_subscription_security.py tests/test_pr_review_api.py`: **24 passed**; ruff clean. Fail-closed global/listing review subscription may break live review UI; restore only with per-event review identity and authorization. Session self subscribers also fail closed due to bare session IDs.
- Ingest/device logging: focused `tests/test_device_auth.py tests/test_session_ingest.py`: **115 passed** after fixing a test-sink initialization ordering bug; ruff clean. Sink tests assert no sentinel transcript text and no device user code.
- Grant races: focused `tests/test_device_auth.py tests/test_token_revocation.py`: **40 passed**, including two simultaneous refreshes, device redemptions and confirmations; ruff clean. These use mocks, not production Redis. Account-wide logout existing tests still pass. Audit Redis version's `GETDEL`, Lua `cjson`/`KEEPTTL` on a fresh instance before deployment.
- Local runtime: `make rebuild` successfully built API/web images but first failed because isolated worktree lacked `.env`. With a permissions-restricted local copy, init then failed safely: local shared Postgres is stamped `033_team_transfer_expiry`, which current upstream main does not contain. **No running API verification; do not downgrade/re-stamp shared DB.** For verification use a fresh isolated Compose project/volumes and then exercise authenticated snapshot isolation and subscription denial.
- Push pre-push `detect-private-key` reports an **unrelated existing file** `tests/test_pr_review_files.py`; skipped only that hook for pushes. Commit hook passed on changed files. No PR created.

## Gate status and adversarial risks

- Gate 0: **NOT PASSED** — contract is a negotiation draft, not a full frozen route family; actual maintainer permission, approved platform policy, aggregate-only live cohort and sender upgrade feasibility not checked. The proposed 10-account suppression is defense in depth, not proof against all differencing; admin trace authorization must remain mandatory.
- Gate S: **PARTIAL ONLY** — fixes above pushed but no independent deployment, no pre-send snapshot redaction, and no comprehensive log-stream/privacy audit. Significant Insights path disabled instead of safe uploader-aware reconstruction; must review.
- Gates 1/1a/2a/2/3/4/5: **NOT PASSED** — grant race mitigation alone does not implement mobile least privilege. No qualified `v2_` clients, projections, retained history/erasure, provenance, platform/person/listing APIs, centrally scoped mobile tokens, stable pagination, database performance checks, running target comparison, signing or installation.
- Never equate prompts to component calls; current client-reported agent ID not verified; existing source TTL/erasure unknown on target. No live person/account data inspected.

## NEXT ACTION (mandatory continuation)

1. Reread `observal-mobile/IMPLEMENTATION_PLAN.md` in full and this checkpoint; coordinate the mobile agent's feedback on overview placement, finalize versioned DTOs/fixtures without claiming endpoints exist.
2. In an isolated main-based worktree implement and regression-test central read-only phone scopes plus atomic refresh/device redemption and device-scoped logout; deny legacy REST/GraphQL/WS write and transcript paths. Independently repair subscription review global paths with scoped payloads if required by UI.
3. Review #1779 against current main for usable projection, explicitly fix sender pre-send secrets and qualified `v2_` uploads; add retained-history/backfill/erasure and original-author publication provenance with event-time checks, then bounded permission-scoped platform/person/Published/detail APIs and stable paging. Every numeric reading needs honest retention/eligibility and real DB tests.
4. After every substantial feature: focused tests, inspect complete diff, adversarial authorization/counting/replay/erasure/performance review, fix and rerun. Verify with an isolated fresh local stack; never modify/downgrade shared local Postgres. Only authorized aggregate-only target checks. Push reviewable branches; write the actual test counts in a new checkpoint. No PR before the user's meaningful full-diff review and explicit authorization.

## Draft PR descriptions for human review only (DO NOT SUBMIT)

- **docs(mobile): negotiate activity v1 contract and synthetic fixtures.** Base upstream main. Proposed permission and coverage semantics, including coarse trace-admin-only platform overview. Requires mobile agent approval/pin; no backend routes. Tests: YAML/JSON parsing and repo hooks. AI-assisted: Pi coding agent (model/version to confirm at submission). Rollout: none.
- **fix(security): isolate layer snapshots and block cross-user Insights content.** Base upstream main, independent of mobile. Regression tests 41 passed. Caveat: significant version-impact content suppressed pending uploader-aware redesign, and no fresh-stack verification yet. Deploy before any new sensitive snapshots. AI-assisted: Pi coding agent (model/version to confirm). No PR before full human diff review.
- **fix(security): restrict GraphQL subscription disclosure.** Base upstream main, independent. Regression tests 24 passed. Caveat: global/listing review feeds and non-admin session subscriptions fail closed pending scoped broadcast redesign; check web UX. AI-assisted: Pi coding agent (model/version to confirm). No PR before full human diff review.
- **fix(security): remove transcript and verification-code content from logs.** Base upstream main, independent. Regression tests 115 passed. AI-assisted: Pi coding agent (model/version to confirm). No PR before full human diff review.
- **fix(auth): atomically consume refresh and device grants.** Base upstream main, independent. Regression tests 40 passed. Does not issue scoped mobile credentials; needs fresh Redis/stack verification. AI-assisted: Pi coding agent (model/version to confirm). No PR before full human diff review.

Compare links: `https://github.com/Observal/Observal/compare/main...Kaushik-Kumar-CEG:Observal:feat/mobile-activity-contract` (replace suffix with each branch above). None are approved to submit or deploy.
