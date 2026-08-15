import { expect, test } from "@playwright/test";

import { mockSession, mockSessionFailure } from "./support/session";

test("uninitialized service offers only local bootstrap guidance", async ({
  page,
}) => {
  await mockSession(page, "uninitialized");
  await page.goto("/");

  await expect(
    page.getByRole("heading", { name: "Administrator not initialized" }),
  ).toBeVisible();
  await expect(page.getByText("acmemux admin bootstrap")).toBeVisible();
  await expect(page.getByLabel("Administrator password")).toHaveCount(0);
  await expect(
    page.getByRole("button", { name: /create|reset|recover/i }),
  ).toHaveCount(0);
});

test("password-only sign-in clears a rejected password", async ({ page }) => {
  await mockSession(page, "signed_out", { signInError: "invalid_credentials" });
  await page.goto("/");

  const password = page.getByLabel("Administrator password");
  await password.fill("test-only-password");
  await page.getByRole("button", { name: "Sign in" }).click();

  await expect(
    page.getByText("Sign-in failed. Check the password and try again."),
  ).toBeVisible();
  await expect(password).toHaveValue("");
  await expect(password).toBeFocused();
});

test("successful sign-in and logout transition through server state", async ({
  page,
}) => {
  await mockSession(page, "signed_out");
  await page.goto("/");

  await page.getByLabel("Administrator password").fill("test-only-password");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(
    page.getByRole("heading", { name: "Certificate operations" }),
  ).toBeVisible();

  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(
    page.getByRole("heading", { name: "Administrator sign in" }),
  ).toBeVisible();
  await expect(page.getByText("Signed out")).toBeVisible();
});

test("expired sessions explain that prior requests are not retried", async ({
  page,
}) => {
  await mockSession(page, "expired");
  await page.goto("/");

  await expect(
    page.getByText("Session expired", { exact: true }),
  ).toBeVisible();
  await expect(
    page.getByText(/no previous request will be retried/i),
  ).toBeVisible();
});

test("origin or CSRF rejection is presented as a blocked request", async ({
  page,
}) => {
  await mockSessionFailure(page, 403, "request_not_allowed");
  await page.goto("/");

  await expect(
    page.getByRole("heading", {
      name: "AcmeMux rejected this browser request",
    }),
  ).toBeVisible();
  await expect(page.getByText(/No request was retried/)).toBeVisible();
  await expect(page.getByText(/permission/i)).toHaveCount(0);
});
