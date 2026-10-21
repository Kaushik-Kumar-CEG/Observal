// SPDX-FileCopyrightText: 2026 Kaushik Kumar <kaushikrjpm10@gmail.com>
// SPDX-License-Identifier: Apache-2.0

import { expect, test } from "@playwright/test";

const code = "AbCdefghijklmnopqrstuvwxyz_123";

test.beforeEach(async ({ page }) => {
  await page.route("**/api/v1/config/public", (route) => route.fulfill({ json: {} }));
  await page.route("**/api/v1/config/version", (route) => route.fulfill({ json: { server_version: "1.16.0-dev.0" } }));
});

test("unauthenticated link drops code before login and never puts it in next", async ({ page }) => {
  await page.goto(`/follow/approve?code=${code}`);
  await expect(page).toHaveURL(/\/login\?next=/);
  expect(page.url()).not.toContain(code);
  expect(new URL(page.url()).searchParams.get("next")).toBe("/follow/approve");
});

test("approval needs a click, sends explicit true, and clears the code after success", async ({ page }) => {
  await page.addInitScript(() => sessionStorage.setItem("observal_access_token", "test-browser-token"));
  let calls = 0;
  await page.route("**/api/v1/mobile-follow-sync/v1/write-approval", async (route) => {
    calls++;
    expect(route.request().postDataJSON()).toEqual({ user_code: code, approve: true });
    expect(route.request().headers().authorization).toBe("Bearer test-browser-token");
    await route.fulfill({ json: { state: "approved" } });
  });
  await page.goto(`/follow/approve?code=${code}`);
  await expect(page).toHaveURL(/\/follow\/approve$/);
  await expect(page.getByLabel(/one-device code/i)).toHaveValue(code);
  expect(calls).toBe(0);
  await page.getByRole("button", { name: "Approve this phone" }).click();
  await expect(page.getByText(/Phone approved/)).toBeVisible();
  await page.screenshot({ path: "/tmp/observal-follow-approve-mock-success.png" });
  expect(calls).toBe(1);
});

test("stale generation and recent sign-in errors give recovery", async ({ page }) => {
  await page.addInitScript(() => sessionStorage.setItem("observal_access_token", "test-browser-token"));
  let status = 409;
  await page.route("**/api/v1/mobile-follow-sync/v1/write-approval", (route) =>
    route.fulfill({ status, json: { error: status === 409 ? "generation_conflict" : "restricted" } }),
  );
  await page.goto("/follow/approve");
  await page.getByLabel(/one-device code/i).fill(code);
  await page.getByRole("button", { name: "Approve this phone" }).click();
  await expect(page.getByRole("alert")).toContainText("no longer valid");
  status = 403;
  await page.getByRole("button", { name: "Approve this phone" }).click();
  await expect(page.getByRole("alert")).toContainText("Sign in again on the same HTTPS server");
  await page.getByRole("button", { name: "Sign in again" }).click();
  await expect(page).toHaveURL(/\/login\?next=/);
  expect(page.url()).not.toContain(code);
});
