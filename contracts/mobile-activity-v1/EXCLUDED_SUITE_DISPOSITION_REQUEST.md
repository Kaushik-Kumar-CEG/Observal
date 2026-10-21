<!-- SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Request for human disposition: 13 failures + 5 errors — NO WAIVER / NOT GREEN

This is a **decision form**, not an agent waiver. Exact names from current focused run `/tmp/mobile-review-excluded-focused.log`: **13 failed, 32 passed, 5 errors**, same 18 names as the prior full `/tmp/mobile071-excluded-suites.log`: **13 failed, 482 passed, 5 errors**. Current *full* server+CLI rerun `/tmp/mobile-review-excluded-current.log` stopped at the 240-second bound without a summary; do **not** call it passing or assume the total. Baseline 068 reproduction in `EXCLUDED_SUITE_TRIAGE_070.md` proves inheritance, **not correctness**. The main `tests/` pass does not execute these tests.

For every row below the responsible named human owner must record one explicit outcome: **FIXED + passing command and SHA**, **BLOCK with issue/owner/target date**, or **time-bounded EXCEPTION with demonstrated unrelatedness, compensating current-route test, expiry, and approving reviewer**. `Historical/inherited`, `obsolete test`, and `agent review` alone are **not** dispositions. Test IDs below are the exact pytest `file::test` unless noted; columns intentionally remain **PENDING**.

| # | Exact nonpassing test | Evidence / proposed owner | Human disposition + reviewer/UTC/evidence |
| --- | --- | --- | --- |
| E1 | `observal-server/tests/test_agent_versions_api.py::test_create_version_happy_path` | Review/version owner: stale `inbox` fixture vs `services.review.cutover` | **PENDING** |
| E2 | `observal-server/tests/test_agent_versions_api.py::test_create_version_co_author_allowed` | Review/version owner: same fixture; co-author authorization unexercised | **PENDING** |
| E3 | `observal-server/tests/test_agent_versions_api.py::test_create_version_warns_multiple_pending` | Review/version owner: same fixture; pending-state validation unexercised | **PENDING** |
| E4 | `observal-server/tests/test_agent_versions_api.py::test_review_version_approve_updates_latest` | Review/version owner: same fixture; approved latest not checked | **PENDING** |
| E5 | `observal-server/tests/test_agent_versions_api.py::test_review_version_reject_stores_reason` | Review/version owner: same fixture; rejection not checked | **PENDING** |
| F1 | `observal-server/tests/test_agent_versions_api.py::test_review_version_non_pending_422` | Review/version owner: removed `_review_agent_version`; exercise current `/reviews` route | **PENDING** |
| F2 | `observal-server/tests/test_agent_versions_api.py::test_review_version_not_found_404` | Review/version owner: same removed helper, no current 404 assertion | **PENDING** |
| F3 | `observal-server/tests/test_component_versions_api.py::test_publish_version_happy_path` | Review/version owner: AsyncMock misses subject/version notification reload; check real disposable DB vs fixture | **PENDING** |
| F4 | `observal-server/tests/test_component_versions_api.py::test_review_version_approve_updates_latest` | Review/version owner: removed `_review_version`; exercise current route | **PENDING** |
| F5 | `observal-server/tests/test_component_versions_api.py::test_review_version_reject_stores_reason` | Review/version owner: same; rejection not checked | **PENDING** |
| F6 | `observal-server/tests/test_component_versions_api.py::test_review_version_non_pending_422` | Review/version owner: same; state transition untested | **PENDING** |
| F7 | `observal-server/tests/test_component_versions_api.py::test_review_version_not_found_404` | Review/version owner: same; no current 404 assertion | **PENDING** |
| F8 | `observal-server/tests/test_component_versions_api.py::test_factory_creates_router[mcp-models.mcp.McpListing-models.mcp.McpVersion]` | Review/version owner: router moved fifth review path to `/reviews` | **PENDING** |
| F9 | `observal-server/tests/test_component_versions_api.py::test_factory_creates_router[skill-models.skill.SkillListing-models.skill.SkillVersion]` | Review/version owner: same; verify separate route | **PENDING** |
| F10 | `observal-server/tests/test_component_versions_api.py::test_factory_creates_router[hook-models.hook.HookListing-models.hook.HookVersion]` | Review/version owner: same; verify separate route | **PENDING** |
| F11 | `observal-server/tests/test_component_versions_api.py::test_factory_creates_router[prompt-models.prompt.PromptListing-models.prompt.PromptVersion]` | Review/version owner: same; verify separate route | **PENDING** |
| F12 | `observal-server/tests/test_component_versions_api.py::test_factory_creates_router[sandbox-models.sandbox.SandboxListing-models.sandbox.SandboxVersion]` | Review/version owner: same; verify separate route | **PENDING** |
| F13 | `observal_cli/tests/test_cmd_component_submit_flags.py::test_every_cli_help_screen_has_copyable_examples` | CLI owner: `registry mcp sync` has 4 examples vs convention ≤3; keep skills/help syntax aligned | **PENDING** |

**Route/version review remains mandatory even if tests are fixed:** the five setup errors never executed their assertions; converting obsolete imports without checking owner scope, review decisions and latest-version state is insufficient. Do not skip, mark xfail or lower assertion counts merely to suppress red. Backend security reviewer must separately accept any time-bounded exception; this manifest author cannot self-disposition.

**Named decision requested:** review/version owner, CLI owner and accountable whole-branch reviewer identities; exact SHA and UTC; outcomes per E1–E5/F1–F13; supporting passing logs or blocking issue links; explicit whether these results block a PR/Flare request. **No response = BLOCKED**, and neither this manifest nor an agent can grant the waiver.
