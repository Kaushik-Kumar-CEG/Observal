<!-- SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Android whole-set decision requested — follow sync 1.0.3 PROPOSAL ONLY

**Backend review packet prepared, not an Android receipt or decision.** Read the CURRENT 1.0.2 CHANGES REQUESTED section of Android-owned `ANDROID_FOLLOW_SYNC_DECISION.md`. Both rejected 1.0.2 and earlier 1.0.1 artifacts retain their reviewed bytes. No 1.0.2 or 1.0.3 sync HTTP, mobile scope, consent storage, migration, browser UI or Android traffic was implemented.

Independently inspect and SHA-256 verify all three **new**, separately named full files under `contracts/mobile-activity-v1/`:

| New artifact | Full-file SHA-256 |
| --- | --- |
| `FOLLOW_SYNC_V103_PROPOSAL.md` | `0ae99e8e1fcec18332518d1fd60ce9c190dd90a2ddd2ede4a79dcc9ad101eb9f` |
| `follow-sync-v103-openapi.yaml` | `ba139625ce38b0643eef1e75e4596dac43682150067e7f28bf0562ae969cba79` |
| `follow-sync-v103-vectors.json` | `b3ad53f15fe0ac5598ad40b9e34aa8705a6f3bdb0aafb0da5e95adb65216427c` |

**At-capacity resolution for review:** strict `limit=100` only and exactly 100 records on every incomplete page, so ≤1,000 pages for up to 100,000 rows. A purpose/owner/generation-bound PostgreSQL read lease has a fixed 30-day expiry and retains materialized current snapshot data or only delta rows ≤60 days old at admission (never beyond 90-day delta retention). The first 429 reserves a lease and returns a signed `retry_cursor`/lease ID; at most one 429 per page across restarts, `Retry-After` ≤60s, healthy-store page processing ≤5s. Even 1,000 worst-case retries/pages take 65,000s (<19h). A >100,000-event change window declines *before the first page* with `snapshot_required`; later concurrent events remain outside the fixed-upper stream. Partial/staged pages, lost responses, expiry, erasure and owner reset never become a committed list/checkpoint. These are proposed server admission/retention obligations, **not** measured throughput or a production-accepted 100K quota.

**Outcome resolution for review:** strict OpenAPI `OperationOutcome.oneOf` couples `effective:true + original_http_status=200` exclusively to `AppliedOperation`, and `effective:true + 409` exclusively to `OperationConflict`. `effective:false` for owner reset/subject erasure permits only a redacted `SupersededOperation` under either original status. Android must also reject path-ID/body-ID or current-generation mismatches not expressible as JSON Schema equality. Both lost-200 and lost-409 positive/negative vectors are included.

The independently requested **entire-set read-only security/contract review happened before hash publication**, found and required fixes to the nonfinal-page-size and first-429 cursor gaps, then rechecked the corrected entire set with no further confirmed contract defect. Local strict proposal tests: **104 passed for 1.0.3; 226 passed across 1.0.1/1.0.2/1.0.3**. The 98 cases are illustrative contract fixtures and model arithmetic, not a running backend or installed two-phone acceptance. A named owner must still decide the per-generation 100,000-subject quota/backup/DSR costs and consent lawful basis/browser disclosure limitations. Real-store saturation, 429, retention, erasure and restart proofs remain for implementation **only after** Android independently records `AGREE` on these exact three hashes. A changed byte requires a fresh whole-set decision.

**Requested Android response:** named reviewer, UTC, independently computed all three hashes, then whole-set **AGREE** or **CHANGES REQUESTED**, including any capacity/consent objections. Do not infer an ACK from this packet, publication to a fork or agent review. Until exact-hash AGREE: **no sync HTTP implementation or transmission**. Human G0, eighteen excluded-suite case dispositions and isolated Flare PAUSE remain separately blocked regardless of a future design decision.
