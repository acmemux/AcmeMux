import { vi } from "vitest";

import {
  CSRF_HEADER_NAME,
  SessionRequestError,
  createSessionClient,
} from "./session";

type FetchImplementation = (
  input: RequestInfo | URL,
  init?: RequestInit,
) => Promise<Response>;

function jsonResponse(value: unknown, init: ResponseInit = {}): Response {
  return new Response(JSON.stringify(value), {
    ...init,
    headers: { "Content-Type": "application/json", ...init.headers },
  });
}

describe("session client", () => {
  it("decodes the bounded authenticated session contract", async () => {
    const request = vi.fn<FetchImplementation>(async () =>
      jsonResponse({
        state: "authenticated",
        idleExpiresAt: "2030-01-01T00:00:00Z",
        absoluteExpiresAt: "2030-01-02T00:00:00Z",
      }),
    );
    const client = createSessionClient({ fetch: request });

    await expect(client.getSession()).resolves.toEqual({
      state: "authenticated",
      idleExpiresAt: "2030-01-01T00:00:00Z",
      absoluteExpiresAt: "2030-01-02T00:00:00Z",
    });
    expect(request).toHaveBeenCalledWith(
      "/api/v1/session",
      expect.objectContaining({
        cache: "no-store",
        credentials: "same-origin",
        method: "GET",
        redirect: "error",
      }),
    );
  });

  it("submits only the password in the sign-in JSON body", async () => {
    const request = vi.fn<FetchImplementation>(async () =>
      jsonResponse({ state: "authenticated" }),
    );
    const client = createSessionClient({ fetch: request });

    await client.signIn("test-only-password");

    const init = request.mock.calls[0]?.[1];
    expect(init?.method).toBe("POST");
    expect(init?.body).toBe(JSON.stringify({ password: "test-only-password" }));
    expect(init?.headers).toEqual({
      Accept: "application/json",
      "Content-Type": "application/json",
    });
  });

  it("reads the CSRF cookie just in time for sign-out", async () => {
    let cookies = "__Host-acmemux_csrf=first-token";
    const request = vi.fn<FetchImplementation>(
      async () => new Response(null, { status: 204 }),
    );
    const client = createSessionClient({
      fetch: request,
      readCookies: () => cookies,
    });

    cookies = "__Host-acmemux_csrf=rotated-token";
    await client.signOut();

    const init = request.mock.calls[0]?.[1];
    expect(init?.method).toBe("DELETE");
    expect(init?.headers).toEqual({
      Accept: "application/json",
      [CSRF_HEADER_NAME]: "rotated-token",
    });
  });

  it("treats a missing sign-out CSRF cookie as an expired session", async () => {
    const request = vi.fn<FetchImplementation>();
    const client = createSessionClient({
      fetch: request,
      readCookies: () => "",
    });

    await expect(client.signOut()).rejects.toMatchObject({
      code: "authentication_required",
      status: 401,
    });
    expect(request).not.toHaveBeenCalled();
  });

  it("does not retain or reflect an authentication error body", async () => {
    const request = vi.fn(async () =>
      jsonResponse(
        {
          error: {
            code: "invalid_credentials",
            message: "sensitive diagnostic that must not be reflected",
          },
        },
        { status: 401 },
      ),
    );
    const client = createSessionClient({ fetch: request });

    const error = await client
      .signIn("test-only-password")
      .catch((value) => value);
    expect(error).toBeInstanceOf(SessionRequestError);
    expect(error).toMatchObject({ code: "invalid_credentials", status: 401 });
    expect(String(error)).not.toContain("sensitive diagnostic");
  });

  it("rejects HTML or unknown states instead of exposing the application", async () => {
    const htmlClient = createSessionClient({
      fetch: vi.fn(
        async () =>
          new Response("<html>not an API response</html>", {
            headers: { "Content-Type": "text/html" },
          }),
      ),
    });
    const unknownClient = createSessionClient({
      fetch: vi.fn(async () => jsonResponse({ state: "administrator" })),
    });

    await expect(htmlClient.getSession()).rejects.toMatchObject({
      code: "invalid_response",
    });
    await expect(unknownClient.getSession()).rejects.toMatchObject({
      code: "invalid_response",
    });
  });

  it("rejects JSON-like content types and maps host rejection safely", async () => {
    const spoofedTypeClient = createSessionClient({
      fetch: vi.fn(
        async () =>
          new Response(JSON.stringify({ state: "authenticated" }), {
            headers: { "Content-Type": "application/jsonp" },
          }),
      ),
    });
    const hostRejectedClient = createSessionClient({
      fetch: vi.fn(async () => new Response(null, { status: 421 })),
    });

    await expect(spoofedTypeClient.getSession()).rejects.toMatchObject({
      code: "invalid_response",
    });
    await expect(hostRejectedClient.getSession()).rejects.toMatchObject({
      code: "request_not_allowed",
      status: 421,
    });
  });

  it.each([
    {
      status: 401,
      bodyCode: "service_unavailable",
      expected: "authentication_required",
    },
    {
      status: 403,
      bodyCode: "session_expired",
      expected: "request_not_allowed",
    },
    {
      status: 421,
      bodyCode: "authentication_required",
      expected: "request_not_allowed",
    },
    {
      status: 503,
      bodyCode: "authentication_required",
      expected: "service_unavailable",
    },
  ])(
    "keeps HTTP $status authoritative over session body code $bodyCode",
    async ({ status, bodyCode, expected }) => {
      const client = createSessionClient({
        fetch: vi.fn(async () =>
          jsonResponse(
            { error: { code: bodyCode, message: "Mismatched error." } },
            { status },
          ),
        ),
      });

      await expect(client.getSession()).rejects.toMatchObject({
        code: expected,
        status,
      });
    },
  );
});
