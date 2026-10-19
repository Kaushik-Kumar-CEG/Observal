-- SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
-- SPDX-License-Identifier: Apache-2.0
-- 002 recreated session_events without 001's raw_line column TTL. Restore it
-- explicitly; the PostgreSQL 067 verifier refuses to open reads without both
-- the 30-day raw-column clock and the configured whole-row clock.
ALTER TABLE session_events MODIFY COLUMN raw_line String CODEC(ZSTD(3)) TTL timestamp + INTERVAL 30 DAY;
