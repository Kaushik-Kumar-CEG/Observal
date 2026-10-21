// SPDX-FileCopyrightText: 2026 Kaushik Kumar <kaushikrjpm10@gmail.com>
// SPDX-License-Identifier: Apache-2.0

import { defineConfig } from "@playwright/test";

// Isolated browser-mock port. Never mutate web/dist mounted by an open QA session.
export default defineConfig({
  testDir: "../tests/e2e",
  timeout: 60_000,
  retries: 0,
  use: { baseURL: "http://127.0.0.1:3034", headless: true, screenshot: "only-on-failure" },
  webServer: {
    command: "pnpm exec vite --host 127.0.0.1 --port 3034 --strictPort",
    port: 3034,
    reuseExistingServer: false,
    timeout: 120_000,
  },
  projects: [{ name: "chromium", use: { browserName: "chromium" } }],
});
