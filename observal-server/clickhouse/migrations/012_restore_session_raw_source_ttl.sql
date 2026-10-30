-- SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
-- SPDX-License-Identifier: Apache-2.0
-- 002 recreated session_events without 001's raw_line column TTL. Restore it
-- explicitly; the PostgreSQL 067 verifier refuses to open reads without both
-- the 30-day raw-column clock and the configured whole-row clock.
-- The migration runner renders the second statement from the validated
-- PostgreSQL data.retention_days value (default 90), never from user SQL.
ALTER TABLE session_events MODIFY COLUMN raw_line String CODEC(ZSTD(3)) TTL timestamp + INTERVAL 30 DAY;
{{SESSION_EVENTS_ROW_RETENTION}};
