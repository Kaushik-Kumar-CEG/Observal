<!-- SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Accountable whole-branch review request — UNSIGNED / G0 PAUSE

**Review target is the actual final `feat/mobile-trace-headlines` fork HEAD recorded by the human at decision time, not merely one runtime commit or an agent assessment.** Baseline for this request: `git merge-base origin/main HEAD` = `6397d1196a50aca4be5e9dd0804e801a3bc98aa7`; prior published branch HEAD `156a7179660535adb18037eefe050942cde54639`, and current Compose-restored-schema runtime successor **`c8c63a3e4179dbc3c8ee897858795e0cbe7f0bf4`**. Later documentary/test commits must be included in the reviewed final HEAD. Fetch the fork branch and compare `git diff origin/main...HEAD`, `git diff --name-status origin/main...HEAD`, `git log --oneline origin/main..HEAD` and `scripts/check_migrations.py`. The earlier `156a7179…` branch changed **303 tracked paths**; `c8c63a3e…` changes **304**, and later documentary commits may increase this count. Recompute at the review decision; a single-commit review is insufficient. The older `HUMAN_REVIEW_070.md` and prior 068 receipts are historical, not sign-off.

**Reviewers requested:** `.github/CODEOWNERS` maps default paths to `@Haz3-jolt @Observal/core` and `/docker/` + `/infra/` to `@Haz3-jolt @Observal/admin`; request an individually named accountable backend privacy/security reviewer, migration/DB operator, and separate review/version + CLI test owners through those groups. CODEOWNERS assignment is **not** an individual signature or disposition. Record reviewer identity/role, UTC decision and **exact 40-character reviewed final fork SHA** below. Agent review, local test pass, fork push and this unsigned request cannot authorize a PR, merge, Flare deployment, protected read, READY or rollout.

| Review area and concrete decision requested | Source/evidence to inspect | Decision / signed finding |
| --- | --- | --- |
| Mobile-only token/device/SCIM and refresh-family race; revocation before access expiry, Redis fail-closed, no desktop/CLI scope change | `api/routes/{auth,device_auth,scim}.py`, `services/{jwt_service,mobile_refresh,token_revocation}.py`; `/tmp/mobile071-postcommit-two-api.log` | **PENDING** |
| 045–069 DB chain, 069 irreversible whole-table update/trigger amplification, accurate statement vs commit time and historical quarantine, old/frozen `xmin`, archived state ordering, restore/failure | `alembic/versions/069_mobile_publication_clock.py`, `services/mobile_publication_clock.py`, `services/mobile_activity_query.py`; `/tmp/mobile071-publication-upgrade.log`; isolated 1K/10K/100K physical restore logs. Candidate-sized WAL/locks/restore **Not recorded** | **PENDING** |
| Privacy: source/finality, ClickHouse raw/row TTL, erasure across scopes, default-closed person reads, no zero-on-missing or forged root/follow permission | `services/mobile_read_control.py`, `jobs/mobile_evidence.py`, `services/retention.py`; `clickhouse/migrations/006_restore_session_raw_source_ttl.sql`; accepted v1.2 SHA set in handoff | **PENDING** |
| Fresh/populated and restored DB boot: commit tracking effective and no pending restart, image-matched init/API/worker; restored 068 cannot launch | `docker/{docker-compose.yml,server-package/docker-compose.yml,entrypoint.sh}`, `services/mobile_boot_preflight.py`, Helm/AWS/Azure/GCP templates; `/tmp/mobile-review-real-restored-gate.log`, `/tmp/mobile-review-compose-boot.log` | **PENDING** |
| Genuine Pi sender/parsers and original-author distinct-root proof; no new telemetry wrapper/OTLP, protected read gating under source/epoch expiry | `services/session_parsers/pi_invocations.py`, `packages/pi-extension`, integration docs | **PENDING** |
| Android exceptions decided **separately**: dual-durable-storage total failure; final confirmed-grant write acknowledgment | Android-owned current handoff and responsible product/security signatory; do not infer exception consent from lifecycle design AGREE | **PENDING** |
| Exact 13 failures + 5 errors, each signed owner disposition | `EXCLUDED_SUITE_DISPOSITION_REQUEST.md`; current focused `/tmp/mobile-review-excluded-focused.log` (13 failed, 32 passed, 5 errors); prior full `/tmp/mobile071-excluded-suites.log` (13 failed, 482 passed, 5 errors). Current full rerun timed out after 240 s; no updated full-suite green claim | **PENDING** |
| Deployment and product GO held until separate controls | `NEW_ISOLATED_FLARE_QUALIFICATION_CHECKLIST.md`, `PRODUCTION_MOBILE_HANDOFF.md`, candidate-specific receipt when supplied | **PENDING** |

**Current local scope:** runtime d19 main `tests/` 10,112 passed/84 skipped/2 subtests; after c8 Compose gate, focused boot tests 11 passed/1 skipped and disposable restored 068 denial → 069 launch 1 passed. 069 100K synthetic migration is **not** a candidate-sized or production p95. No Helm binary or Terraform executable on current PATH; earlier d19 Helm render/format checks are historical, current Helm/cloud rollout **Not recorded**. Two Compose `config --format json` renders with disposable empty env files passed image parity, flag and per-process gate checks; files were deleted and no stack started.

**Frozen decisions:** accepted four v1.2 artifacts unchanged. Android's written exact-hash 1.0.1 decision is **CHANGES REQUESTED**, not AGREE (Android HEAD `491c93077b80fa864fefe7877d65cb39ade1f316`). Preserve reviewed proposal SHA `f88b2fde15f6a3dc904aaa606d2f854b78565cb016c2839fc2dc985b5a796193` and its attachments as historic immutable evidence; no sync HTTP while successor version and owner policy decisions are pending. No proposal agreement is implied by backend review.

## Human response form — NO DECISION RECORDED

- Accountable reviewer name / affiliation / role: **Not supplied**
- Reviewed final fork commit SHA (40 characters): **Not supplied**
- UTC timestamp / review medium or signed receipt link: **Not supplied**
- Privacy/security findings, severities, fixes and residual risk owner: **Not supplied**
- 069 irreversible upgrade and effective commit-clock operational decision: **Not supplied**
- Review/version and CLI owners' **per-case** dispositions from linked manifest: **Not supplied**
- Android security exception decisions (two separate recorded approvals/denials): **Not supplied**
- Decision for **source review only** (approve / changes required / reject): **Not supplied**
- A source-review approval is not Flare inventory, deployment, protected preflight, Android READY, PR authorization or production release.

Do not fill blanks with agent conclusions, assumed owner identities or an inherited baseline. Any changes after the human SHA need explicit re-review or a narrow recorded addendum before moving gates.
