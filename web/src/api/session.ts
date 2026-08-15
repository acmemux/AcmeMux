export const CSRF_COOKIE_NAME = "__Host-acmemux_csrf";
export const CSRF_HEADER_NAME = "X-AcmeMux-CSRF";

export type PublicSessionSnapshot =
  | { state: "uninitialized" }
  | { state: "signed_out" }
  | { state: "expired" }
  | {
      state: "authenticated";
      idleExpiresAt?: string;
      absoluteExpiresAt?: string;
    };

export type AuthenticatedSession = Extract<
  PublicSessionSnapshot,
  { state: "authenticated" }
>;

export type SessionSnapshot = PublicSessionSnapshot;

export type SessionErrorCode =
  | "invalid_credentials"
  | "authentication_required"
  | "session_expired"
  | "request_not_allowed"
  | "rate_limited"
  | "service_unavailable"
  | "invalid_response"
  | "network_failure";

export class SessionRequestError extends Error {
  readonly code: SessionErrorCode;
  readonly status: number;

  constructor(code: SessionErrorCode, status: number) {
    super(safeErrorMessage(code));
    this.name = "SessionRequestError";
    this.code = code;
    this.status = status;
  }
}

export interface SessionClient {
  getSession(): Promise<SessionSnapshot>;
  signIn(password: string): Promise<SessionSnapshot>;
  signOut(): Promise<void>;
}

type SessionClientOptions = {
  fetch?: typeof globalThis.fetch;
  readCookies?: () => string;
};

const knownErrorCodes = new Set<SessionErrorCode>([
  "invalid_credentials",
  "authentication_required",
  "session_expired",
  "request_not_allowed",
  "rate_limited",
  "service_unavailable",
]);

function safeErrorMessage(code: SessionErrorCode): string {
  switch (code) {
    case "invalid_credentials":
      return "Sign-in failed.";
    case "authentication_required":
    case "session_expired":
      return "The administrator session ended.";
    case "request_not_allowed":
      return "The browser request was blocked.";
    case "rate_limited":
      return "Sign-in is temporarily limited.";
    case "service_unavailable":
    case "network_failure":
      return "The session service is unavailable.";
    case "invalid_response":
      return "The session service returned an invalid response.";
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function optionalString(
  value: Record<string, unknown>,
  key: string,
): string | undefined {
  const field = value[key];
  if (field === undefined) {
    return undefined;
  }
  if (typeof field !== "string" || field.length === 0) {
    throw new SessionRequestError("invalid_response", 0);
  }
  return field;
}

function decodeSession(value: unknown): PublicSessionSnapshot {
  if (!isRecord(value) || typeof value.state !== "string") {
    throw new SessionRequestError("invalid_response", 0);
  }

  switch (value.state) {
    case "uninitialized":
    case "signed_out":
    case "expired":
      return { state: value.state };
    case "authenticated":
      return {
        state: "authenticated",
        idleExpiresAt: optionalString(value, "idleExpiresAt"),
        absoluteExpiresAt: optionalString(value, "absoluteExpiresAt"),
      };
    default:
      throw new SessionRequestError("invalid_response", 0);
  }
}

function readCookie(name: string, source: string): string | undefined {
  const prefix = `${encodeURIComponent(name)}=`;
  for (const segment of source.split(";")) {
    const candidate = segment.trim();
    if (!candidate.startsWith(prefix)) {
      continue;
    }
    try {
      return decodeURIComponent(candidate.slice(prefix.length));
    } catch {
      return undefined;
    }
  }
  return undefined;
}

async function readJSON(response: Response): Promise<unknown> {
  const contentType = response.headers.get("content-type") ?? "";
  if (!isJSONContentType(contentType)) {
    throw new SessionRequestError("invalid_response", response.status);
  }
  try {
    return await response.json();
  } catch {
    throw new SessionRequestError("invalid_response", response.status);
  }
}

function isJSONContentType(value: string): boolean {
  return value.split(";", 1)[0]?.trim().toLowerCase() === "application/json";
}

function fallbackCode(status: number): SessionErrorCode {
  switch (status) {
    case 401:
      return "authentication_required";
    case 403:
    case 421:
      return "request_not_allowed";
    case 429:
      return "rate_limited";
    case 503:
      return "service_unavailable";
    default:
      return "invalid_response";
  }
}

async function responseError(
  response: Response,
  allowInvalidCredentials = false,
): Promise<SessionRequestError> {
  if (response.status === 403 || response.status === 421) {
    return new SessionRequestError("request_not_allowed", response.status);
  }
  if (response.status === 401 && !allowInvalidCredentials) {
    return new SessionRequestError("authentication_required", 401);
  }
  let code = fallbackCode(response.status);
  const contentType = response.headers.get("content-type") ?? "";
  if (isJSONContentType(contentType)) {
    try {
      const body: unknown = await response.json();
      if (
        isRecord(body) &&
        isRecord(body.error) &&
        typeof body.error.code === "string" &&
        knownErrorCodes.has(body.error.code as SessionErrorCode)
      ) {
        const presented = body.error.code as SessionErrorCode;
        if (
          allowInvalidCredentials &&
          response.status === 401 &&
          presented === "invalid_credentials"
        ) {
          code = presented;
        } else if (
          presented !== "invalid_credentials" &&
          presented !== "authentication_required" &&
          presented !== "session_expired" &&
          presented !== "request_not_allowed"
        ) {
          code = presented;
        }
      }
    } catch {
      // The response body is deliberately not retained or reflected.
    }
  }
  return new SessionRequestError(code, response.status);
}

export function createSessionClient(
  options: SessionClientOptions = {},
): SessionClient {
  const request =
    options.fetch ??
    ((input: RequestInfo | URL, init?: RequestInit) =>
      globalThis.fetch(input, init));
  const readCookies =
    options.readCookies ??
    (() => (typeof document === "undefined" ? "" : document.cookie));

  async function fetchSession(init: RequestInit): Promise<SessionSnapshot> {
    let response: Response;
    try {
      response = await request("/api/v1/session", {
        cache: "no-store",
        credentials: "same-origin",
        redirect: "error",
        ...init,
      });
    } catch {
      throw new SessionRequestError("network_failure", 0);
    }
    if (!response.ok) {
      throw await responseError(response, init.method === "POST");
    }

    return decodeSession(await readJSON(response));
  }

  return {
    getSession() {
      return fetchSession({
        headers: { Accept: "application/json" },
        method: "GET",
      });
    },
    signIn(password: string) {
      return fetchSession({
        body: JSON.stringify({ password }),
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
        },
        method: "POST",
      });
    },
    async signOut() {
      const csrfToken = readCookie(CSRF_COOKIE_NAME, readCookies());
      if (!csrfToken) {
        throw new SessionRequestError("authentication_required", 401);
      }
      let response: Response;
      try {
        response = await request("/api/v1/session", {
          cache: "no-store",
          credentials: "same-origin",
          headers: {
            Accept: "application/json",
            [CSRF_HEADER_NAME]: csrfToken,
          },
          method: "DELETE",
          redirect: "error",
        });
      } catch {
        throw new SessionRequestError("network_failure", 0);
      }
      if (!response.ok) {
        throw await responseError(response);
      }
      if (response.status !== 204) {
        throw new SessionRequestError("invalid_response", response.status);
      }
    },
  };
}

export const browserSessionClient = createSessionClient();
