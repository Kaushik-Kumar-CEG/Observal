<!-- SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Backend-owned trace-first v1.1 draft (mobile review requested)

This contract supersedes the *undeployed* calls-first v1 negotiation, **not** an existing deployed API or the mobile repo's older pinned bytes. The branch also contains a partial v1 read API that does not yet conform to this future paired-window contract. The wire is prospective and `trace_headlines` MUST stay false until run lineage, privacy/erasure, eligibility and real-store scale qualifications pass. Do not connect live UI to a nonconforming route; keep the demo strictly synthetic. Mobile-owner acknowledgement of this new pin is outstanding.

SHA-256 of these exact bytes:

- `openapi.yaml`: `2ab13a2f5d036f0878778b9e5aefcb0bd1a2051406b71ce8e5dc48dff47ac66b`
- `fixtures.json`: `ea5889fd8a889b1afde30fecd8570b431cf6773ca3e4f3db0f0c55df892f907a`
- `responses.json`: `2665a939b0c064fd51e8ca1c4728b4d582868740e59e51bae229324b3af55cdf`
- `contract-vectors.json`: `dac646cbaa236296c04cfb93a151caebe610f0dc84b7946433a65939733b4529`

**Backend arithmetic decision:** Author and User readings are separate distinct `(actor, verified run-incarnation)` root unions after event-time provenance and current visibility filtering. A root used by two components contributes one to each component row but only one to the person union. Forty attributable calls on one verified root contribute **one** trace. A verified **unprompted** root with attributable activity contributes a component trace but never a general prompted session. A missing or ambiguous parent link, reused legacy session ID or absent run-origin proof contributes no verified trace. Counts are partial or unavailable until all relevant kinds are qualified; installed components, generic sessions and usage pings are not substitute evidence. Unsupported zero is never a measured zero. The existing Pi projection's parent-free/prompt-required root guess does **not** meet this standard; the trace headline capability remains off.

The schema retains separately scoped, default-off device grant, refresh and phone-family logout routes. No target-server permissions, privacy-policy sign-off or upgraded production sender cohort is asserted by synthetic fixtures. Human full-diff review is required before a PR; no merge or deployment is authorized.
