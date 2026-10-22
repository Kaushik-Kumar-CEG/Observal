// SPDX-FileCopyrightText: 2026 Kaushik Kumar <kaushikrjpm10@gmail.com>
// SPDX-License-Identifier: Apache-2.0

import { expect, test } from "@playwright/test";

test.beforeEach(async ({ page }) => {
  await page.route("**/api/v1/config/public", (route) => route.fulfill({ json: {} }));
  await page.route("**/api/v1/config/version", (route) => route.fulfill({ json: { server_version: "1.16.0-dev.0" } }));
});

test("signed-out browser routes to login without recording consent", async ({ page }) => {
  let posts = 0;
  await page.route("**/api/v1/mobile-follow-sync/v1/consent", (route) => { posts++; return route.fulfill({ json: {} }); });
  await page.goto("/follow/consent");
  await expect(page).toHaveURL(/\/login\?next=/);
  expect(new URL(page.url()).searchParams.get("next")).toBe("/follow/consent");
  expect(posts).toBe(0);
});

test("owner must check explicit consent after reading account state", async ({ page }) => {
  await page.addInitScript(() => sessionStorage.setItem("observal_access_token", "test-browser-token"));
  await page.route("**/api/v1/mobile-follow-sync/v1/consent/state", (route) =>
    route.fulfill({ json: { state: "consent_required", owner_generation: 4 } }),
  );
  let posts = 0;
  await page.route("**/api/v1/mobile-follow-sync/v1/consent", async (route) => {
    posts++;
    const body = route.request().postDataJSON();
    expect(body).toMatchObject({ consent: true, owner_generation: 4 });
    expect(body.consent_id).toMatch(/^[0-9a-f-]{36}$/i);
    expect(route.request().headers().authorization).toBe("Bearer test-browser-token");
    await route.fulfill({ json: { state: "available", owner_generation: 4 } });
  });
  await page.goto("/follow/consent");
  const button = page.getByRole("button", { name: "Enable account following" });
  await expect(button).toBeDisabled();
  expect(posts).toBe(0);
  await page.screenshot({ path: "/tmp/observal-follow-consent-desktop-form.png" });
  await page.setViewportSize({ width: 390, height: 844 });
  await page.screenshot({ path: "/tmp/observal-follow-consent-mobile-form.png", fullPage: true });
  await page.getByRole("checkbox").check();
  await expect(button).toBeEnabled();
  await button.click();
  await expect(page.getByRole("status")).toContainText("Account following is available");
  expect(posts).toBe(1);
  await page.screenshot({ path: "/tmp/observal-follow-consent-mocked.png" });
});

test("account settings offers consent only when the gated server state is reachable", async ({ page }) => {
  await page.addInitScript(() => {
    sessionStorage.setItem("observal_access_token", "test-browser-token");
    localStorage.setItem("observal_user_role", "user");
  });
  await page.route("**/api/v1/mobile-follow-sync/v1/consent/state", (route) =>
    route.fulfill({ json: { state: "consent_required", owner_generation: 2 } }),
  );
  await page.goto("/account");
  const consentLink = page.getByRole("link", { name: "Review consent" });
  await expect(consentLink).toBeVisible();
  await consentLink.scrollIntoViewIfNeeded();
  await page.screenshot({ path: "/tmp/observal-follow-account-consent-entry.png" });
  await consentLink.click();
  await expect(page).toHaveURL(/\/follow\/consent$/);
  await expect(page.getByRole("button", { name: "Enable account following" })).toBeDisabled();
});

test("default-closed follow route never advertises account opt-in", async ({ page }) => {
  await page.addInitScript(() => {
    sessionStorage.setItem("observal_access_token", "test-browser-token");
    localStorage.setItem("observal_user_role", "user");
  });
  await page.route("**/api/v1/mobile-follow-sync/v1/consent/state", (route) =>
    route.fulfill({ status: 404, json: { detail: "Not Found" } }),
  );
  await page.goto("/account");
  await expect(page.getByRole("heading", { name: "Profile" })).toBeVisible();
  await expect(page.getByRole("link", { name: "Review consent" })).toHaveCount(0);
});

test("blocked or pending state never offers opt-in", async ({ page }) => {
  await page.addInitScript(() => sessionStorage.setItem("observal_access_token", "test-browser-token"));
  await page.route("**/api/v1/mobile-follow-sync/v1/consent/state", (route) =>
    route.fulfill({ json: { state: "withdrawal_pending", owner_generation: 5 } }),
  );
  await page.goto("/follow/consent");
  await expect(page.getByText(/waiting for removal/i)).toBeVisible();
  await expect(page.getByRole("button", { name: "Enable account following" })).toHaveCount(0);
});
