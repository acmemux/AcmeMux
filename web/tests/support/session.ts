import type { Page } from "@playwright/test";

type SessionState =
  "uninitialized" | "signed_out" | "expired" | "authenticated";

type SessionMockOptions = {
  signInError?: "invalid_credentials" | "rate_limited" | "request_not_allowed";
};

const csrfCookie = {
  name: "__Host-acmemux_csrf",
  value: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
};

async function installCsrfCookie(page: Page) {
  await page.addInitScript(({ name, value }) => {
    // Vite serves browser suites over HTTP, where Chromium correctly rejects
    // a Secure __Host- cookie. This browser-only transport mock preserves the
    // exact cookie name without weakening production cookie behavior.
    Object.defineProperty(document, "cookie", {
      configurable: true,
      get: () => `${encodeURIComponent(name)}=${encodeURIComponent(value)}`,
      set: () => undefined,
    });
  }, csrfCookie);
}

export async function mockSession(
  page: Page,
  initialState: SessionState = "authenticated",
  options: SessionMockOptions = {},
) {
  let state = initialState;
  await installCsrfCookie(page);

  await page.route("**/api/v1/session", async (route) => {
    const request = route.request();
    switch (request.method()) {
      case "GET":
        await route.fulfill({
          body: JSON.stringify({ state }),
          contentType: "application/json",
          status: 200,
        });
        return;
      case "POST": {
        if (options.signInError) {
          const status =
            options.signInError === "rate_limited"
              ? 429
              : options.signInError === "request_not_allowed"
                ? 403
                : 401;
          await route.fulfill({
            body: JSON.stringify({
              error: { code: options.signInError, message: "Request rejected" },
            }),
            contentType: "application/json",
            status,
          });
          return;
        }
        state = "authenticated";
        await route.fulfill({
          body: JSON.stringify({ state }),
          contentType: "application/json",
          status: 200,
        });
        return;
      }
      case "DELETE":
        if (request.headers()["x-acmemux-csrf"] !== csrfCookie.value) {
          await route.fulfill({
            body: JSON.stringify({
              error: {
                code: "request_not_allowed",
                message: "Request rejected",
              },
            }),
            contentType: "application/json",
            status: 403,
          });
          return;
        }
        state = "signed_out";
        await route.fulfill({ status: 204 });
        return;
      default:
        await route.fulfill({ status: 405 });
    }
  });
}

export async function mockSessionFailure(
  page: Page,
  status: 403 | 503,
  code: "request_not_allowed" | "service_unavailable",
) {
  await page.route("**/api/v1/session", async (route) => {
    await route.fulfill({
      body: JSON.stringify({ error: { code, message: "Request rejected" } }),
      contentType: "application/json",
      status,
    });
  });
}
