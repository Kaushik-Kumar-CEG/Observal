<!-- SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Backend integration contract — pending mobile-agent review

This directory is the backend implementation's **draft v1** wire shape, not the mobile client's existing pinned contract or a deployed server. Compare with the mobile client's current pin before adopting it; do not silently substitute this contract for the older `9cb8f9f3` checkpoint. The mobile agent's later Gate 0 trace/run-incarnation proposal is separate, unratified negotiation material and is **not** implemented by these v1 routes.

SHA-256 (exact file bytes):

- `openapi.yaml`: `5231fc1b52504fa118446dfa06f3b321592638c22b219f65df182139bbd7e1b2`
- `fixtures.json`: `751f0ffbf53e92a0d11557bf34fd8b5157c5a83a239ed2becda7ac5ac6f5730e`
- `responses.json`: `c42829e43d8d1e19b5f88c0904691cb8cb4b85043c9411061e8d3fc1d1a526e5`

Changes from the older pin include the explicitly scoped device grant/rotation/logout, bounded people and component routes, original-author Published items, nested component observations, and partial versus privacy-suppressed coverage. These examples are **synthetic**, not a qualified live cohort. Only source-verified, uploader-bound upgraded Pi senders can contribute prompted roots; component root counts additionally require a verified preceding user prompt. Unsupported skill/hook readings stay null. General prompted roots are independent from MCP calls: 40 verified calls in one prompted root count as one root, not 40. Author usage and user usage must never be conflated.

`mobile.auth_enabled` stays off until maintainers approve the security and privacy policy, the target server is independently qualified and the mobile client explicitly acknowledges the changed contract. No PR, merge or deployment is authorized by this checkpoint.
