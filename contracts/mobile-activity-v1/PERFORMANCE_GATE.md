<!-- SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Mobile 12-subject performance gate — **500 ms not qualified**

`MOBILE_INTEGRATION_SCALE=1 MOBILE_TRACE_EXPLAIN=1` on a disposable loopback PostgreSQL 18 stack inserts 100 follows and 10,000 root facts inside a rollback-only transaction. It asserts one root for 40 calls, overlapping component rows, original-author transfer, visibility and scope invalidation. It does **not** represent production hardware or live source ingestion. The v3 HTTPS proof has far fewer roots and cannot qualify this budget.

| Probe | Measured ms | Notes |
|---|---:|---|
| Earlier 12-subject mixed-viewport p95 | 656.6 | 27 sampled pages, most without the 10K-root author; **not a representative heavy-card p95** |
| Representative 12-subject 10K-root first read | 479.6 / 647.5 / 574.6 | Three isolated reruns; cold includes setup/cache variability |
| Representative same-viewport warm p95 | 556.1 / 790.1 / 647.7 | Twelve repeats per run; **all exceed 500** |
| Representative privacy-filtered p95 | 277.2 / 297.7 / 340.0 | One large listing private, original-author scope constrained |
| PostgreSQL planner without hash preference | 1196.7 cold, 1254.6 warm p95 | A controlled `SET LOCAL enable_nestloop=on` run in the same transaction; the current forced hash plan is necessary on this fixture |

`EXPLAIN (ANALYZE, BUFFERS)` of the author predicate showed a 10K-row `mobile_run_instances` scan (~34 ms in one sample), a ~12K-row visibility/run hash-join chain and a distinct-root sort (one sample ~552 ms). A proposed stringified UUID pair key was tested and **reverted** after a 1216 ms mixed-viewport p95; it would not safely reduce the distinct-root workload. Removing the transaction-local hash preference produced >1 s representative reads and was also reverted. Cold and warm latency vary materially under concurrent ClickHouse/API/worker container load; neither this nor an isolated p95 justifies silently increasing the 500 ms target.

**Product decision required before a qualified rollout:** either retain 500 ms as a hard gate and commission a dedicated query/denormalization optimization with source, privacy-epoch, approval-time and deletion invariants, or explicitly accept an alternative UX/SLO (for example, show 12-card skeletons while background work completes and set a separately reviewed p95 on target hardware). Do not cache named counts without epoch/source/retention invalidation. Do not turn slow/unknown into zero or show general-session totals as a substitute. Measure production-like hardware and approval/privacy mixes **only after owner authorization**; the current backend does not pass the proposed budget.
