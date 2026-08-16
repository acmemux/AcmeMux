import { CSRF_COOKIE_NAME, CSRF_HEADER_NAME } from "./session";

const MAX_PATH_BYTES = 4095;
const MAX_DISPLAY_BYTES = 4096;
const MAX_OUTPUT_BYTES = 256 * 1024;
const MAX_CERTIFICATES = 256;
const MAX_PREVIEW_CERTIFICATES = 64;
const MAX_DOMAINS = 100;

const operationIdPattern = /^[a-f0-9]{32}$/;
const previewTokenPattern = /^[A-Za-z0-9_-]{43}$/;
const manifestIdPattern = /^[a-z0-9][a-z0-9._-]{0,127}$/;
const identifierPattern = /^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$/;
const reasonCodePattern = /^[a-z][a-z0-9_]{0,63}$/;
const releaseIdentityPattern =
  /^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/;
const revisionIdentityPattern = /^[a-f0-9]{40}$/;

const acceptedCAs = new Set([
  "googletrust",
  "googletrust-staging",
  "https://acme-staging-v02.api.letsencrypt.org/directory",
  "https://acme.godaddy.com/v1/acme/directory",
  "https://acme.ssl.com/sslcom-dv-ecc",
  "https://acme.ssl.com/sslcom-dv-rsa",
  "https://acme.zerossl.com/v2/DV90",
  "https://acme-v02.api.letsencrypt.org/directory",
  "https://dv.acme-v02.api.pki.goog/directory",
  "https://dv.acme-v02.test-api.pki.goog/directory",
  "letsencrypt",
  "letsencrypt-staging",
  "sslcomecc",
  "sslcomrsa",
  "zerossl",
]);

export type OperationPolicy = {
  browserDisconnect: "continues";
  cancellation: "not_supported";
  retry: "manual_only";
  timeoutSeconds: number;
};

export type ManualOperationIntent = {
  kind: "manual_workspace_run";
  workingDirectory: string;
  configurationPath: string;
  storagePath: string;
  runtime: {
    identity: string;
    manifestId: string;
  };
  certificates: Array<{
    name: string;
    domains: string[];
    account: string;
    ca: string;
    challenge: {
      name: string;
      kind: "http-01" | "dns-01";
      mode:
        | "listener"
        | "webroot"
        | "cloudflare"
        | "digitalocean"
        | "duckdns"
        | "azuredns"
        | "route53";
    };
  }>;
  cloudAccess: Array<{
    challengeName: string;
    provider: "azuredns" | "route53";
    authMode:
      | "env"
      | "wli"
      | "msi"
      | "cli"
      | "oidc"
      | "pipeline"
      | "static"
      | "shared_profile"
      | "instance_role"
      | "static+assume_role"
      | "shared_profile+assume_role"
      | "instance_role+assume_role";
    files: string[];
    helper: string | null;
    metadata: string | null;
  }>;
  nativeEffects: [
    "acme_accounts_may_change",
    "certificate_artifacts_may_change",
    "native_configuration_backup_may_change",
    "external_acme_state_may_change",
  ];
};

export type ManualOperationPreview = {
  state: "review_required";
  reviewedPreviewToken: string;
  intent: ManualOperationIntent;
  policy: OperationPolicy;
};

export type ActiveOperation = {
  id: string;
  kind: "manual";
  state: "queued" | "running";
  phase: "queued" | "revalidating" | "executing" | "refreshing_inventory";
  requestedAt: string;
  startedAt: string | null;
};

export type OperationStatus =
  { state: "idle" } | { state: "active"; operation: ActiveOperation };

export type CertificateOperationResult = {
  name: string;
  state: "completed" | "failed" | "not_attempted" | "ambiguous";
  reasonCode: string;
};

export type TerminalOperationResult = {
  id: string;
  kind: "manual";
  state:
    | "succeeded"
    | "failed"
    | "partial"
    | "not_attempted"
    | "timed_out"
    | "interrupted"
    | "incompatible"
    | "ambiguous";
  reasonCode: string;
  requestedAt: string;
  startedAt: string | null;
  finishedAt: string;
  mayHaveChanged: boolean;
  output: {
    text: string;
    truncated: boolean;
  };
  certificates: CertificateOperationResult[];
  inventory:
    | {
        state: "refreshed";
        certificateCount: number;
        summary: string;
      }
    | {
        state: "refresh_failed";
        certificateCount: null;
        summary: string;
      };
};

export type LatestOperation =
  { state: "empty" } | { state: "available"; result: TerminalOperationResult };

export type OperationErrorCode =
  | "authentication_required"
  | "request_not_allowed"
  | "invalid_request"
  | "operation_active"
  | "operation_changed"
  | "recovery_required"
  | "workspace_invalid"
  | "configuration_invalid"
  | "service_busy"
  | "service_unavailable"
  | "invalid_response"
  | "network_failure";

export class OperationRequestError extends Error {
  readonly code: OperationErrorCode;
  readonly status: number;

  constructor(code: OperationErrorCode, status: number) {
    super(operationErrorMessage(code));
    this.name = "OperationRequestError";
    this.code = code;
    this.status = status;
  }
}

export interface OperationClient {
  getStatus(): Promise<OperationStatus>;
  getLatest(): Promise<LatestOperation>;
  getCancelPolicy(): Promise<OperationPolicy>;
  previewManual(): Promise<ManualOperationPreview>;
  enqueueManual(reviewedPreviewToken: string): Promise<ActiveOperation>;
}

type OperationClientOptions = {
  fetch?: typeof globalThis.fetch;
  readCookies?: () => string;
};

const knownErrorCodes = new Set<OperationErrorCode>([
  "authentication_required",
  "request_not_allowed",
  "invalid_request",
  "operation_active",
  "operation_changed",
  "recovery_required",
  "workspace_invalid",
  "configuration_invalid",
  "service_busy",
  "service_unavailable",
]);

function operationErrorMessage(code: OperationErrorCode): string {
  switch (code) {
    case "authentication_required":
      return "The administrator session ended.";
    case "request_not_allowed":
      return "The protected operation request was blocked.";
    case "invalid_request":
      return "The operation request was invalid.";
    case "operation_active":
      return "A native workspace operation is already active.";
    case "operation_changed":
      return "The reviewed operation is no longer current.";
    case "recovery_required":
      return "Native configuration recovery is required before an operation can start.";
    case "workspace_invalid":
      return "The selected native workspace is not safe to operate.";
    case "configuration_invalid":
      return "The native configuration is not eligible for managed execution.";
    case "service_busy":
      return "Another native workspace action is in progress.";
    case "service_unavailable":
    case "network_failure":
      return "Operation status is unavailable.";
    case "invalid_response":
      return "The operation service returned an invalid response.";
  }
}

function invalidResponse(status = 0): never {
  throw new OperationRequestError("invalid_response", status);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasExactKeys(
  value: Record<string, unknown>,
  required: readonly string[],
): boolean {
  const allowed = new Set(required);
  return (
    required.every((key) => Object.prototype.hasOwnProperty.call(value, key)) &&
    Object.keys(value).every((key) => allowed.has(key))
  );
}

function containsUnsafeControl(value: string, multiline = false): boolean {
  return Array.from(value).some((character) => {
    const point = character.codePointAt(0) ?? 0;
    if (multiline && (point === 0x09 || point === 0x0a)) return false;
    return point < 0x20 || point === 0x7f;
  });
}

function boundedText(
  value: unknown,
  maximumBytes = MAX_DISPLAY_BYTES,
  options: { allowEmpty?: boolean; multiline?: boolean } = {},
): value is string {
  return (
    typeof value === "string" &&
    (options.allowEmpty || value.length > 0) &&
    new TextEncoder().encode(value).length <= maximumBytes &&
    !containsUnsafeControl(value, options.multiline)
  );
}

function validCanonicalPath(value: unknown): value is string {
  if (
    !boundedText(value, MAX_PATH_BYTES) ||
    !value.startsWith("/") ||
    new TextEncoder().encode(value).length > MAX_PATH_BYTES
  ) {
    return false;
  }
  if (value === "/") return true;
  return (
    !value.endsWith("/") &&
    !value
      .slice(1)
      .split("/")
      .some(
        (component) =>
          component === "" || component === "." || component === "..",
      )
  );
}

function validTimestamp(value: unknown): value is string {
  if (!boundedText(value, 64)) return false;
  const match =
    /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?Z$/.exec(
      value,
    );
  if (!match) return false;
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = Number(match[6]);
  const fractional = match[7];
  const leapYear = year % 400 === 0 || (year % 4 === 0 && year % 100 !== 0);
  const days = [31, leapYear ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  return (
    year >= 1 &&
    month >= 1 &&
    month <= 12 &&
    day >= 1 &&
    day <= (days[month - 1] ?? 0) &&
    hour <= 23 &&
    minute <= 59 &&
    second <= 59 &&
    (fractional === undefined || !fractional.endsWith("0"))
  );
}

function timestampOrder(left: string, right: string): boolean {
  return Date.parse(left) <= Date.parse(right);
}

function safeInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && Number(value) >= 0;
}

function decodePolicy(value: unknown): OperationPolicy {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      "browserDisconnect",
      "cancellation",
      "retry",
      "timeoutSeconds",
    ]) ||
    value.browserDisconnect !== "continues" ||
    value.cancellation !== "not_supported" ||
    value.retry !== "manual_only" ||
    !safeInteger(value.timeoutSeconds) ||
    value.timeoutSeconds < 1 ||
    value.timeoutSeconds > 24 * 60 * 60
  ) {
    invalidResponse();
  }
  return {
    browserDisconnect: "continues",
    cancellation: "not_supported",
    retry: "manual_only",
    timeoutSeconds: value.timeoutSeconds,
  };
}

function decodePreviewCertificate(
  value: unknown,
): ManualOperationIntent["certificates"][number] {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, ["name", "domains", "account", "ca", "challenge"]) ||
    typeof value.name !== "string" ||
    !identifierPattern.test(value.name) ||
    typeof value.account !== "string" ||
    !identifierPattern.test(value.account) ||
    typeof value.ca !== "string" ||
    !acceptedCAs.has(value.ca) ||
    !Array.isArray(value.domains) ||
    value.domains.length < 1 ||
    value.domains.length > MAX_DOMAINS ||
    !value.domains.every((domain) => boundedText(domain, 253)) ||
    new Set(value.domains).size !== value.domains.length ||
    !isRecord(value.challenge) ||
    !hasExactKeys(value.challenge, ["name", "kind", "mode"]) ||
    typeof value.challenge.name !== "string" ||
    !identifierPattern.test(value.challenge.name) ||
    (value.challenge.kind !== "http-01" && value.challenge.kind !== "dns-01") ||
    (value.challenge.kind === "http-01" &&
      value.challenge.mode !== "listener" &&
      value.challenge.mode !== "webroot") ||
    (value.challenge.kind === "dns-01" &&
      value.challenge.mode !== "cloudflare" &&
      value.challenge.mode !== "digitalocean" &&
      value.challenge.mode !== "duckdns" &&
      value.challenge.mode !== "azuredns" &&
      value.challenge.mode !== "route53")
  ) {
    invalidResponse();
  }
  return {
    name: value.name,
    domains: [...value.domains] as string[],
    account: value.account,
    ca: value.ca,
    challenge: {
      name: value.challenge.name,
      kind: value.challenge.kind,
      mode: value.challenge
        .mode as ManualOperationIntent["certificates"][number]["challenge"]["mode"],
    },
  };
}

const cloudAuthModes = new Set([
  "env",
  "wli",
  "msi",
  "cli",
  "oidc",
  "pipeline",
  "static",
  "shared_profile",
  "instance_role",
  "static+assume_role",
  "shared_profile+assume_role",
  "instance_role+assume_role",
]);

function decodeCloudAccess(
  value: unknown,
): ManualOperationIntent["cloudAccess"][number] {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      "challengeName",
      "provider",
      "authMode",
      "files",
      "helper",
      "metadata",
    ]) ||
    typeof value.challengeName !== "string" ||
    !identifierPattern.test(value.challengeName) ||
    (value.provider !== "azuredns" && value.provider !== "route53") ||
    typeof value.authMode !== "string" ||
    !cloudAuthModes.has(value.authMode) ||
    !Array.isArray(value.files) ||
    value.files.length > 8 ||
    !value.files.every(validCanonicalPath) ||
    (value.helper !== null && !validCanonicalPath(value.helper)) ||
    (value.metadata !== null && !boundedText(value.metadata, 128))
  )
    invalidResponse();
  return {
    challengeName: value.challengeName,
    provider: value.provider,
    authMode:
      value.authMode as ManualOperationIntent["cloudAccess"][number]["authMode"],
    files: [...value.files] as string[],
    helper: value.helper as string | null,
    metadata: value.metadata as string | null,
  };
}

const nativeEffects: ManualOperationIntent["nativeEffects"] = [
  "acme_accounts_may_change",
  "certificate_artifacts_may_change",
  "native_configuration_backup_may_change",
  "external_acme_state_may_change",
];

function decodeIntent(value: unknown): ManualOperationIntent {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      "kind",
      "workingDirectory",
      "configurationPath",
      "storagePath",
      "runtime",
      "certificates",
      "cloudAccess",
      "nativeEffects",
    ]) ||
    value.kind !== "manual_workspace_run" ||
    !validCanonicalPath(value.workingDirectory) ||
    !validCanonicalPath(value.configurationPath) ||
    !validCanonicalPath(value.storagePath) ||
    !isRecord(value.runtime) ||
    !hasExactKeys(value.runtime, ["identity", "manifestId"]) ||
    typeof value.runtime.identity !== "string" ||
    (!releaseIdentityPattern.test(value.runtime.identity) &&
      !revisionIdentityPattern.test(value.runtime.identity)) ||
    typeof value.runtime.manifestId !== "string" ||
    !manifestIdPattern.test(value.runtime.manifestId) ||
    !Array.isArray(value.certificates) ||
    value.certificates.length < 1 ||
    value.certificates.length > MAX_PREVIEW_CERTIFICATES ||
    !Array.isArray(value.cloudAccess) ||
    value.cloudAccess.length > MAX_PREVIEW_CERTIFICATES ||
    !Array.isArray(value.nativeEffects) ||
    value.nativeEffects.length !== nativeEffects.length ||
    !nativeEffects.every(
      (effect, index) => (value.nativeEffects as unknown[])[index] === effect,
    )
  ) {
    invalidResponse();
  }
  const certificates = value.certificates.map(decodePreviewCertificate);
  const cloudAccess = value.cloudAccess.map(decodeCloudAccess);
  if (
    certificates.some(
      (certificate, index) =>
        index > 0 && certificates[index - 1]!.name >= certificate.name,
    )
  ) {
    invalidResponse();
  }
  return {
    kind: "manual_workspace_run",
    workingDirectory: value.workingDirectory,
    configurationPath: value.configurationPath,
    storagePath: value.storagePath,
    runtime: {
      identity: value.runtime.identity,
      manifestId: value.runtime.manifestId,
    },
    certificates,
    cloudAccess,
    nativeEffects: [...nativeEffects],
  };
}

function decodePreview(value: unknown): ManualOperationPreview {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      "state",
      "reviewedPreviewToken",
      "intent",
      "policy",
    ]) ||
    value.state !== "review_required" ||
    typeof value.reviewedPreviewToken !== "string" ||
    !previewTokenPattern.test(value.reviewedPreviewToken)
  ) {
    invalidResponse();
  }
  return {
    state: "review_required",
    reviewedPreviewToken: value.reviewedPreviewToken,
    intent: decodeIntent(value.intent),
    policy: decodePolicy(value.policy),
  };
}

function decodeActiveOperation(value: unknown): ActiveOperation {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      "id",
      "kind",
      "state",
      "phase",
      "requestedAt",
      "startedAt",
    ]) ||
    typeof value.id !== "string" ||
    !operationIdPattern.test(value.id) ||
    value.kind !== "manual" ||
    (value.state !== "queued" && value.state !== "running") ||
    (value.phase !== "queued" &&
      value.phase !== "revalidating" &&
      value.phase !== "executing" &&
      value.phase !== "refreshing_inventory") ||
    !validTimestamp(value.requestedAt) ||
    (value.startedAt !== null && !validTimestamp(value.startedAt)) ||
    (value.state === "queued" &&
      (value.phase !== "queued" || value.startedAt !== null)) ||
    (value.state === "running" &&
      (value.phase === "queued" || value.startedAt === null)) ||
    (value.startedAt !== null &&
      !timestampOrder(value.requestedAt, value.startedAt))
  ) {
    invalidResponse();
  }
  return {
    id: value.id,
    kind: "manual",
    state: value.state,
    phase: value.phase,
    requestedAt: value.requestedAt,
    startedAt: value.startedAt,
  };
}

function decodeStatus(value: unknown): OperationStatus {
  if (!isRecord(value) || typeof value.state !== "string") invalidResponse();
  if (value.state === "idle") {
    if (!hasExactKeys(value, ["state"])) invalidResponse();
    return { state: "idle" };
  }
  if (value.state === "active" && hasExactKeys(value, ["state", "operation"])) {
    return {
      state: "active",
      operation: decodeActiveOperation(value.operation),
    };
  }
  invalidResponse();
}

function decodeCertificateResult(value: unknown): CertificateOperationResult {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, ["name", "state", "reasonCode"]) ||
    typeof value.name !== "string" ||
    !identifierPattern.test(value.name) ||
    (value.state !== "completed" &&
      value.state !== "failed" &&
      value.state !== "not_attempted" &&
      value.state !== "ambiguous") ||
    typeof value.reasonCode !== "string" ||
    !reasonCodePattern.test(value.reasonCode)
  ) {
    invalidResponse();
  }
  return {
    name: value.name,
    state: value.state,
    reasonCode: value.reasonCode,
  };
}

function decodeInventory(value: unknown): TerminalOperationResult["inventory"] {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, ["state", "certificateCount", "summary"]) ||
    !boundedText(value.summary)
  ) {
    invalidResponse();
  }
  if (value.state === "refreshed" && safeInteger(value.certificateCount)) {
    return {
      state: "refreshed",
      certificateCount: value.certificateCount,
      summary: value.summary,
    };
  }
  if (value.state === "refresh_failed" && value.certificateCount === null) {
    return {
      state: "refresh_failed",
      certificateCount: null,
      summary: value.summary,
    };
  }
  invalidResponse();
}

function decodeTerminalResult(value: unknown): TerminalOperationResult {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      "id",
      "kind",
      "state",
      "reasonCode",
      "requestedAt",
      "startedAt",
      "finishedAt",
      "mayHaveChanged",
      "output",
      "certificates",
      "inventory",
    ]) ||
    typeof value.id !== "string" ||
    !operationIdPattern.test(value.id) ||
    value.kind !== "manual" ||
    (value.state !== "succeeded" &&
      value.state !== "failed" &&
      value.state !== "partial" &&
      value.state !== "not_attempted" &&
      value.state !== "timed_out" &&
      value.state !== "interrupted" &&
      value.state !== "incompatible" &&
      value.state !== "ambiguous") ||
    typeof value.reasonCode !== "string" ||
    !reasonCodePattern.test(value.reasonCode) ||
    !validTimestamp(value.requestedAt) ||
    (value.startedAt !== null && !validTimestamp(value.startedAt)) ||
    !validTimestamp(value.finishedAt) ||
    !timestampOrder(value.requestedAt, value.finishedAt) ||
    (value.startedAt !== null &&
      (!timestampOrder(value.requestedAt, value.startedAt) ||
        !timestampOrder(value.startedAt, value.finishedAt))) ||
    typeof value.mayHaveChanged !== "boolean" ||
    !isRecord(value.output) ||
    !hasExactKeys(value.output, ["text", "truncated"]) ||
    !boundedText(value.output.text, MAX_OUTPUT_BYTES, {
      allowEmpty: true,
      multiline: true,
    }) ||
    typeof value.output.truncated !== "boolean" ||
    !Array.isArray(value.certificates) ||
    value.certificates.length > MAX_CERTIFICATES
  ) {
    invalidResponse();
  }
  const certificates = value.certificates.map(decodeCertificateResult);
  if (
    new Set(certificates.map(({ name }) => name)).size !== certificates.length
  ) {
    invalidResponse();
  }
  return {
    id: value.id,
    kind: "manual",
    state: value.state,
    reasonCode: value.reasonCode,
    requestedAt: value.requestedAt,
    startedAt: value.startedAt,
    finishedAt: value.finishedAt,
    mayHaveChanged: value.mayHaveChanged,
    output: { text: value.output.text, truncated: value.output.truncated },
    certificates,
    inventory: decodeInventory(value.inventory),
  };
}

function decodeLatest(value: unknown): LatestOperation {
  if (!isRecord(value) || typeof value.state !== "string") invalidResponse();
  if (value.state === "empty") {
    if (!hasExactKeys(value, ["state"])) invalidResponse();
    return { state: "empty" };
  }
  if (value.state === "available" && hasExactKeys(value, ["state", "result"])) {
    return { state: "available", result: decodeTerminalResult(value.result) };
  }
  invalidResponse();
}

function isJSONContentType(value: string): boolean {
  return value.split(";", 1)[0]?.trim().toLowerCase() === "application/json";
}

async function readJSON(response: Response): Promise<unknown> {
  if (!isJSONContentType(response.headers.get("content-type") ?? "")) {
    invalidResponse(response.status);
  }
  try {
    return await response.json();
  } catch {
    invalidResponse(response.status);
  }
}

function readCookie(name: string, source: string): string | undefined {
  const prefix = `${encodeURIComponent(name)}=`;
  for (const segment of source.split(";")) {
    const candidate = segment.trim();
    if (!candidate.startsWith(prefix)) continue;
    try {
      return decodeURIComponent(candidate.slice(prefix.length));
    } catch {
      return undefined;
    }
  }
  return undefined;
}

function fallbackCode(status: number): OperationErrorCode {
  switch (status) {
    case 400:
    case 413:
    case 415:
      return "invalid_request";
    case 401:
      return "authentication_required";
    case 403:
    case 421:
      return "request_not_allowed";
    case 409:
      return "operation_changed";
    case 429:
      return "service_busy";
    case 503:
      return "service_unavailable";
    default:
      return "invalid_response";
  }
}

async function responseError(
  response: Response,
): Promise<OperationRequestError> {
  if (response.status === 401) {
    return new OperationRequestError("authentication_required", 401);
  }
  if (response.status === 403 || response.status === 421) {
    return new OperationRequestError("request_not_allowed", response.status);
  }
  let code = fallbackCode(response.status);
  if (isJSONContentType(response.headers.get("content-type") ?? "")) {
    try {
      const value: unknown = await response.json();
      if (
        isRecord(value) &&
        hasExactKeys(value, ["error"]) &&
        isRecord(value.error) &&
        hasExactKeys(value.error, ["code", "message"]) &&
        typeof value.error.code === "string" &&
        knownErrorCodes.has(value.error.code as OperationErrorCode) &&
        boundedText(value.error.message, 1024)
      ) {
        const presented = value.error.code as OperationErrorCode;
        if (
          presented !== "authentication_required" &&
          presented !== "request_not_allowed"
        ) {
          code = presented;
        }
      }
    } catch {
      // Error bodies are never retained or reflected.
    }
  }
  return new OperationRequestError(code, response.status);
}

export function createOperationClient(
  options: OperationClientOptions = {},
): OperationClient {
  const request =
    options.fetch ??
    ((input: RequestInfo | URL, init?: RequestInit) =>
      globalThis.fetch(input, init));
  const readCookies =
    options.readCookies ??
    (() => (typeof document === "undefined" ? "" : document.cookie));

  async function send(
    path: string,
    init: RequestInit,
    expectedStatus: number,
    mutation = false,
  ): Promise<unknown> {
    const headers = new Headers(init.headers);
    headers.set("Accept", "application/json");
    if (mutation) {
      const csrf = readCookie(CSRF_COOKIE_NAME, readCookies());
      if (!csrf) {
        throw new OperationRequestError("authentication_required", 401);
      }
      headers.set(CSRF_HEADER_NAME, csrf);
      headers.set("Content-Type", "application/json");
    }
    let response: Response;
    try {
      response = await request(path, {
        cache: "no-store",
        credentials: "same-origin",
        redirect: "error",
        ...init,
        headers,
      });
    } catch {
      throw new OperationRequestError("network_failure", 0);
    }
    if (!response.ok) throw await responseError(response);
    if (response.status !== expectedStatus) invalidResponse(response.status);
    return readJSON(response);
  }

  return {
    async getStatus() {
      return decodeStatus(
        await send("/api/v1/operations/status", { method: "GET" }, 200),
      );
    },
    async getLatest() {
      return decodeLatest(
        await send("/api/v1/operations/latest", { method: "GET" }, 200),
      );
    },
    async getCancelPolicy() {
      const value = await send(
        "/api/v1/operations/cancel-policy",
        { method: "GET" },
        200,
      );
      if (!isRecord(value) || !hasExactKeys(value, ["policy"])) {
        invalidResponse();
      }
      return decodePolicy(value.policy);
    },
    async previewManual() {
      return decodePreview(
        await send(
          "/api/v1/operations/manual/previews",
          { body: "{}", method: "POST" },
          200,
          true,
        ),
      );
    },
    async enqueueManual(reviewedPreviewToken) {
      if (!previewTokenPattern.test(reviewedPreviewToken)) {
        throw new OperationRequestError("invalid_request", 0);
      }
      const value = await send(
        "/api/v1/operations/manual",
        {
          body: JSON.stringify({ reviewedPreviewToken }),
          method: "POST",
        },
        202,
        true,
      );
      if (!isRecord(value) || !hasExactKeys(value, ["operation"])) {
        invalidResponse();
      }
      return decodeActiveOperation(value.operation);
    },
  };
}

export const browserOperationClient = createOperationClient();
