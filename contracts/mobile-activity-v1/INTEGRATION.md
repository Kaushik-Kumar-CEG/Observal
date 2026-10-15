<!-- SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Backend-owned trace-first v1.1 draft (mobile review requested)

This contract supersedes the *undeployed* calls-first v1 negotiation, **not** an existing deployed API or the mobile repo's older pinned bytes. This branch implements a draft paired-window and component-page route subset, but no independently verified run-origin witness or qualified production evidence exists. The wire is prospective and `trace_headlines` MUST stay false until run lineage, privacy/erasure, eligibility and real-store scale qualifications pass. Do not connect live UI to unqualified readings; keep the demo strictly synthetic. Mobile-owner acknowledgement of this new pin is outstanding.

SHA-256 of these exact bytes:

- `openapi.yaml`: `a3b5c50430f140f40723c8cb93d9ace6b15c3eea35e6962f217ed77c4b38d404`
- `fixtures.json`: `ea5889fd8a889b1afde30fecd8570b431cf6773ca3e4f3db0f0c55df892f907a`
- `responses.json`: `2665a939b0c064fd51e8ca1c4728b4d582868740e59e51bae229324b3af55cdf`
- `contract-vectors.json`: `41ab916c05c9607447e5c48c4ec687ff6ab9e6df5b0b885c4b0828dadbf3f9a6`

**Backend arithmetic decision:** Author and User readings are separate distinct `(actor, verified run-incarnation)` root unions after event-time provenance and current visibility filtering. A root used by two components contributes one to each component row but only one to the person union. Forty attributable calls on one verified root contribute **one** trace. A verified **unprompted** root with attributable activity contributes a component trace but never a general prompted session. A missing or ambiguous parent link, reused legacy session ID or absent run-origin proof contributes no verified trace. Counts are partial or unavailable until all relevant kinds are qualified; installed components, generic sessions and usage pings are not substitute evidence. Unsupported zero is never a measured zero. The Pi sender supplies a scoped collision fence, not independent run-origin attestation; the trace headline capability remains off.

Following mobile-owner review, this revision proposes a count-free `{status: restricted}` for each forbidden scope in a mixed twelve-person batch (including a self User reading while Author is forbidden), and singular `1 observed trace` copy. Completely denied batches and restricted individual endpoints remain bodyless 403. The reverse Author-allowed/User-forbidden wire is schema-valid but current roles grant no such permission. **This is a new pin requiring explicit mobile-owner acceptance; do not replace its old pinned bytes yet.**

The schema retains separately scoped, default-off device grant, refresh and phone-family logout routes. No target-server permissions, privacy-policy sign-off or upgraded production sender cohort is asserted by synthetic fixtures. Human full-diff review is required before a PR; no merge or deployment is authorized.
