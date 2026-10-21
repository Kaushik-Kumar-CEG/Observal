<!-- SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Current focused excluded-suite triage — unsigned, G0 blocked

At backend worktree baseline `166dd27037665230c02bf88e465994489a609266`, reran the **unmodified** three affected files:

```text
pytest -q observal-server/tests/test_agent_versions_api.py observal-server/tests/test_component_versions_api.py observal_cli/tests/test_cmd_component_submit_flags.py
13 failed, 32 passed, 5 errors in 2.32s
/tmp/mobile104-excluded-focused-current.log
```

The exact 18 IDs and unsigned per-case disposition fields remain in `EXCLUDED_SUITE_DISPOSITION_REQUEST.md` (E1–E5/F1–F13). This reproduction is NOT a clean full `observal-server/tests/`+`observal_cli/tests/` result. The previously attempted complete rerun stopped at its 240-second bound; do not extrapolate.

**Concrete new detail for F13 (not a disposition):** The fail-fast assertion first reaches the four-examples `observal registry mcp sync` group. A local, uncommitted attempt to reduce both group and command help to three examples exposed the next failure: `observal review` lacks examples. Enumerating the entire command tree revealed **30 additional commands/groups without any examples**, comprising `observal review` and its subcommands plus `observal admin mobile-test-{status,setup,open,revoke}`. The temporary CLI-only changes were reverted; do not fix F13 by weakening/skipping the original test or by recording only the first fail-fast path. The accountable CLI/review owners must decide whether to supply accurate copyable examples for every affected command, or give a signed per-case BLOCK/exception with a current-route compensation and expiry.

**Server cases remain uncovered:** five setup errors from obsolete review/version fixture imports prevent their assertions from running; the eight other server failures include removed review helper/route shapes and one mocked notification reload. These are leads, not proof of unrelatedness. The review/version owner should cover live current `/reviews` owner authorization, 404/422, approval/rejection/latest-version transitions and notification reload on a disposable DB before signing E1–E5/F1–F12. No production or Flare DB was touched. Source-test edits made solely to mark these tests green would not constitute human review.

Local installation/upgrade checks run independently: migration chain reports **72 linear revisions, head 069** (`/tmp/mobile104-migration-linearity.log`); scoped auth, ClickHouse retention assertions and boot guards yielded **37 passed, 1 skipped, 1 Authlib warning** (`/tmp/mobile104-independent-install-auth-ttl.log`); separate browser and entrypoint boot smoke **14 passed, 1 skipped** (`/tmp/mobile104-independent-install-boot.log`). A freshly started, uniquely named **loopback-only disposable PostgreSQL 18** with `track_commit_timestamp=on` ran `test_mobile_upgrade_restore_postgres.py`, `test_publication_clock_postgres.py` and `test_fresh_migrations_postgres.py`: **3 passed in 12.81 seconds** (`/tmp/mobile104-disposable-postgres-install-upgrade.log`). The physical populated 068 backup→distinct restored DB→069 quarantine and fresh upgrade tests created/dropped their own synthetic databases; scratch container was removed and name-filtered Docker process check found no remaining scratch container. This is NOT Flare, installed-artifact or candidate-sized proof. Skips do not replace representative candidate backup/restore, current Helm/Terraform validation, operator digests or candidate-sized WAL/lock proof. **All 18 human disposition fields remain PENDING.**
