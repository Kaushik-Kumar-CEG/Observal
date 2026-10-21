<!-- SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Android decision requested — follow sync 1.0.2 proposal ONLY

**Delivery status: backend-side review packet prepared; Android receipt/decision NOT recorded.** Do not mistake this document for an Android reply. The three rejected 1.0.1 files remain separately intact, with their previously reviewed SHA-256s `f88b2fde15f6a3dc904aaa606d2f854b78565cb016c2839fc2dc985b5a796193`, `009e9d345d25b69dfa93501fbfc01c878901cadc3de35c22eea9ea59d2aa2aae`, `807f06aec8da230d98faf214526923f71c7c793830b41aa253dbbfc09de015ac` (Android CHANGES REQUESTED). Do not edit Android-owned files or copy this packet over its decision.

Please independently hash and review the **entire new set**:

| File under `contracts/mobile-activity-v1/` | SHA-256 (full file) |
| --- | --- |
| `FOLLOW_SYNC_V102_PROPOSAL.md` | `7d062a9f01041c04415aeeb58b741bb9ba10a1e18cef1f7a2e6d9490a67297bb` |
| `follow-sync-v102-openapi.yaml` | `c788dd7c9c44e678dcaeb990272a821d7010fc71734797e716b1af7ba1fd9001` |
| `follow-sync-v102-vectors.json` | `74801ddbfadecbd06818fa787260a9e2813be346561aed751c151d58f916e130` |

The proposal addresses generation-fenced remove-all (including unseen base-0 queued edits); account-wide withdrawal, browser-account re-consent, revocation and retained ACK lookup; availability-only older-server 404/405 and negative versions; and JS-safe exact integers, bounded strings/cursors and complete URL. It contains 72 illustrative cases, including linked two-phone races and independent pagination fixtures. Strict local proposal tests: **76 passed**; the original 1.0.1 test still passes **46**. Independent read-only adversarial passes checked each document and reported no *remaining confirmed* P0/P1 contradiction in those targeted paths. These are not executable server or Android acceptance tests.

**Decide only on this exact whole set:** Android records `AGREE` or `CHANGES REQUESTED`, plus reviewer, UTC, independently observed three SHA-256s, and any UX/privacy exception. In particular review the disclosed limitation that a same-owner desktop bearer can call consent without cryptographically proving it viewed the browser disclosure page, as well as the proposed **per-generation** 100,000-subject limit and lawful-basis policy pending named owner decision. On any changed byte, review a newly hashed set rather than interpreting the decision as partial. Until an exact-hash AGREE and independent owner decisions exist: **no sync endpoint, write grant, follow storage, new mobile traffic or rollout**. Flare/G0 remain PAUSE.
