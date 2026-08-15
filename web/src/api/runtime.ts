import { CSRF_COOKIE_NAME, CSRF_HEADER_NAME } from "./session";

// Linux PATH_MAX includes the terminating NUL byte.
export const MAX_RUNTIME_PATH_LENGTH = 4095;

export type CompatibilityState = "supported" | "unverified" | "incompatible";

export type RuntimeCompatibilityCode =
  | "compatible"
  | "unknown_identity"
  | "unsupported_platform"
  | "executable_digest_mismatch"
  | "version_output_mismatch"
  | "build_evidence_missing"
  | "build_evidence_incomplete"
  | "build_module_mismatch"
  | "build_version_mismatch"
  | "build_toolchain_mismatch"
  | "build_dependency_mismatch"
  | "build_platform_mismatch"
  | "build_revision_mismatch"
  | "build_modified"
  | "observation_invalid"
  | "manifest_changed";

export type RuntimeEvidence = {
  canonicalPath: string;
  version: string | null;
  commit: string | null;
  versionOutput: string;
  platform: {
    os: string;
    architecture: string;
  };
  metadata: {
    sizeBytes: number;
    modifiedAt: string;
    changedAt: string;
    mode: string;
    capabilities: "none" | "cap_net_bind_service=ep";
    uid: number;
    gid: number;
    device: string;
    inode: string;
  };
  build: {
    available: boolean;
    provenanceComplete: boolean;
    goVersion: string;
    commandPath: string;
    mainPath: string;
    mainVersion: string;
    dependencyGraphSha256: string;
    goos: string;
    goarch: string;
    vcsRevision: string;
    vcsModifiedKnown: boolean;
    vcsModifiedValid: boolean;
    vcsModified: boolean;
  };
  sha256: string;
};

export type RuntimeCompatibility = {
  state: CompatibilityState;
  code: RuntimeCompatibilityCode;
  manifestId?: string;
  summary: string;
};

export type RuntimeDiagnosticState =
  "missing" | "unsafe" | "changed" | "malformed_output" | "timed_out";

export type RuntimeDiagnosticCode =
  | "path_required"
  | "path_not_absolute"
  | "path_not_canonical"
  | "path_too_long"
  | "path_unavailable"
  | "symlink_not_allowed"
  | "not_regular"
  | "empty_executable"
  | "executable_too_large"
  | "untrusted_owner"
  | "unsafe_permissions"
  | "unsafe_capabilities"
  | "not_executable"
  | "fingerprint_failed"
  | "changed_during_inspection"
  | "inspection_timeout"
  | "inspection_canceled"
  | "probe_timeout"
  | "probe_canceled"
  | "probe_output_limit"
  | "probe_failed"
  | "malformed_version_output"
  | "executable_not_qualified"
  | "build_identity_mismatch"
  | "unsupported_platform"
  | "platform_mismatch"
  | "executable_replaced";

export type RuntimeDiagnostic = {
  code: RuntimeDiagnosticCode;
  message: string;
};

export type RuntimeSnapshot =
  | { state: "unselected" }
  | {
      state: CompatibilityState;
      runtime: RuntimeEvidence;
      compatibility: RuntimeCompatibility;
    }
  | {
      state: RuntimeDiagnosticState;
      path: string;
      diagnostic: RuntimeDiagnostic;
      runtime?: RuntimeEvidence;
    };

export type RuntimeCandidate =
  | {
      state: "review_required";
      candidate: RuntimeEvidence;
      compatibility: RuntimeCompatibility;
      reviewedEvidenceSha256?: string;
    }
  | {
      state: Exclude<RuntimeDiagnosticState, "changed">;
      path: string;
      diagnostic: RuntimeDiagnostic;
    };

export type RuntimeErrorCode =
  | "authentication_required"
  | "request_not_allowed"
  | "invalid_request"
  | "runtime_changed"
  | "service_unavailable"
  | "invalid_response"
  | "network_failure";

export class RuntimeRequestError extends Error {
  readonly code: RuntimeErrorCode;
  readonly status: number;

  constructor(code: RuntimeErrorCode, status: number) {
    super(runtimeErrorMessage(code));
    this.name = "RuntimeRequestError";
    this.code = code;
    this.status = status;
  }
}

export interface RuntimeClient {
  getRuntime(): Promise<RuntimeSnapshot>;
  inspectCandidate(path: string): Promise<RuntimeCandidate>;
  adoptCandidate(
    candidate: RuntimeEvidence,
    manifestId: string,
    reviewedEvidenceSha256: string,
  ): Promise<RuntimeSnapshot>;
}

type RuntimeClientOptions = {
  fetch?: typeof globalThis.fetch;
  readCookies?: () => string;
};

const selectedStates = new Set<CompatibilityState>([
  "supported",
  "unverified",
  "incompatible",
]);
const compatibilityCodes = new Set<RuntimeCompatibilityCode>([
  "compatible",
  "unknown_identity",
  "unsupported_platform",
  "executable_digest_mismatch",
  "version_output_mismatch",
  "build_evidence_missing",
  "build_evidence_incomplete",
  "build_module_mismatch",
  "build_version_mismatch",
  "build_toolchain_mismatch",
  "build_dependency_mismatch",
  "build_platform_mismatch",
  "build_revision_mismatch",
  "build_modified",
  "observation_invalid",
  "manifest_changed",
]);
const diagnosticStates = new Set<RuntimeDiagnosticState>([
  "missing",
  "unsafe",
  "changed",
  "malformed_output",
  "timed_out",
]);
const candidateDiagnosticStates = new Set([
  "missing",
  "unsafe",
  "malformed_output",
  "timed_out",
]);
const diagnosticCodes = new Set<RuntimeDiagnosticCode>([
  "path_required",
  "path_not_absolute",
  "path_not_canonical",
  "path_too_long",
  "path_unavailable",
  "symlink_not_allowed",
  "not_regular",
  "empty_executable",
  "executable_too_large",
  "untrusted_owner",
  "unsafe_permissions",
  "unsafe_capabilities",
  "not_executable",
  "fingerprint_failed",
  "changed_during_inspection",
  "inspection_timeout",
  "inspection_canceled",
  "probe_timeout",
  "probe_canceled",
  "probe_output_limit",
  "probe_failed",
  "malformed_version_output",
  "executable_not_qualified",
  "build_identity_mismatch",
  "unsupported_platform",
  "platform_mismatch",
  "executable_replaced",
]);
const manifestIdPattern = /^[a-z0-9][a-z0-9._-]{0,127}$/;
const knownErrorCodes = new Set<RuntimeErrorCode>([
  "authentication_required",
  "request_not_allowed",
  "invalid_request",
  "runtime_changed",
  "service_unavailable",
]);

function runtimeErrorMessage(code: RuntimeErrorCode): string {
  switch (code) {
    case "authentication_required":
      return "The administrator session ended.";
    case "request_not_allowed":
      return "The runtime request was blocked.";
    case "invalid_request":
      return "The runtime request was invalid.";
    case "runtime_changed":
      return "The executable changed before it could be adopted.";
    case "service_unavailable":
    case "network_failure":
      return "Runtime status is unavailable.";
    case "invalid_response":
      return "The runtime service returned an invalid response.";
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasExactKeys(
  value: Record<string, unknown>,
  required: readonly string[],
  optional: readonly string[] = [],
): boolean {
  const keys = Object.keys(value);
  const allowed = new Set([...required, ...optional]);
  return (
    required.every((key) => Object.prototype.hasOwnProperty.call(value, key)) &&
    keys.every((key) => allowed.has(key))
  );
}

function boundedString(value: unknown, maximum = 4096): value is string {
  return (
    typeof value === "string" && value.length > 0 && value.length <= maximum
  );
}

function safeInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && Number(value) >= 0;
}

function decodePlatform(value: unknown): RuntimeEvidence["platform"] {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, ["os", "architecture"]) ||
    !boundedString(value.os, 64) ||
    !boundedString(value.architecture, 64)
  ) {
    throw new RuntimeRequestError("invalid_response", 0);
  }
  return { os: value.os, architecture: value.architecture };
}

function decodeMetadata(value: unknown): RuntimeEvidence["metadata"] {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      "sizeBytes",
      "modifiedAt",
      "changedAt",
      "mode",
      "capabilities",
      "uid",
      "gid",
      "device",
      "inode",
    ]) ||
    !safeInteger(value.sizeBytes) ||
    !boundedString(value.modifiedAt, 64) ||
    !boundedString(value.changedAt, 64) ||
    !boundedString(value.mode, 32) ||
    (value.capabilities !== "none" &&
      value.capabilities !== "cap_net_bind_service=ep") ||
    !safeInteger(value.uid) ||
    !safeInteger(value.gid) ||
    !boundedString(value.device, 64) ||
    !boundedString(value.inode, 64)
  ) {
    throw new RuntimeRequestError("invalid_response", 0);
  }
  return {
    sizeBytes: value.sizeBytes,
    modifiedAt: value.modifiedAt,
    changedAt: value.changedAt,
    mode: value.mode,
    capabilities: value.capabilities,
    uid: value.uid,
    gid: value.gid,
    device: value.device,
    inode: value.inode,
  };
}

function decodeBuild(value: unknown): RuntimeEvidence["build"] {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      "goVersion",
      "available",
      "provenanceComplete",
      "commandPath",
      "mainPath",
      "mainVersion",
      "dependencyGraphSha256",
      "goos",
      "goarch",
      "vcsRevision",
      "vcsModifiedKnown",
      "vcsModifiedValid",
      "vcsModified",
    ]) ||
    typeof value.available !== "boolean" ||
    typeof value.provenanceComplete !== "boolean" ||
    !boundedString(value.goVersion, 128) ||
    !boundedString(value.commandPath, 256) ||
    !boundedString(value.mainPath, 256) ||
    !boundedString(value.mainVersion, 256) ||
    typeof value.dependencyGraphSha256 !== "string" ||
    !/^[a-f0-9]{64}$/.test(value.dependencyGraphSha256) ||
    !boundedString(value.goos, 32) ||
    !boundedString(value.goarch, 32) ||
    typeof value.vcsRevision !== "string" ||
    !/^[a-f0-9]{40}$/.test(value.vcsRevision) ||
    typeof value.vcsModifiedKnown !== "boolean" ||
    typeof value.vcsModifiedValid !== "boolean" ||
    typeof value.vcsModified !== "boolean"
  ) {
    throw new RuntimeRequestError("invalid_response", 0);
  }
  return {
    available: value.available,
    provenanceComplete: value.provenanceComplete,
    goVersion: value.goVersion,
    commandPath: value.commandPath,
    mainPath: value.mainPath,
    mainVersion: value.mainVersion,
    dependencyGraphSha256: value.dependencyGraphSha256,
    goos: value.goos,
    goarch: value.goarch,
    vcsRevision: value.vcsRevision,
    vcsModifiedKnown: value.vcsModifiedKnown,
    vcsModifiedValid: value.vcsModifiedValid,
    vcsModified: value.vcsModified,
  };
}

function nullableIdentity(value: unknown): value is string | null {
  return value === null || boundedString(value, 256);
}

function decodeEvidence(value: unknown): RuntimeEvidence {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      "canonicalPath",
      "version",
      "commit",
      "versionOutput",
      "platform",
      "metadata",
      "build",
      "sha256",
    ]) ||
    !boundedString(value.canonicalPath, MAX_RUNTIME_PATH_LENGTH) ||
    runtimePathError(value.canonicalPath) !== undefined ||
    !nullableIdentity(value.version) ||
    !nullableIdentity(value.commit) ||
    (value.version === null) === (value.commit === null) ||
    !boundedString(value.versionOutput, 256) ||
    typeof value.sha256 !== "string" ||
    !/^[a-f0-9]{64}$/.test(value.sha256)
  ) {
    throw new RuntimeRequestError("invalid_response", 0);
  }
  const platform = decodePlatform(value.platform);
  const build = decodeBuild(value.build);
  const releaseValid =
    value.version === null ||
    /^v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/.test(value.version);
  const revisionValid =
    value.commit === null || /^[a-f0-9]{40}$/.test(value.commit);
  const identity = value.version ?? value.commit;
  const outputIdentityMatches =
    identity !== null &&
    (value.versionOutput ===
      `lego version ${identity} ${platform.os}/${platform.architecture}` ||
      (value.version !== null &&
        value.versionOutput ===
          `lego version ${value.version.slice(1)} ${platform.os}/${platform.architecture}`));
  if (
    !releaseValid ||
    !revisionValid ||
    !outputIdentityMatches ||
    !build.available ||
    !build.provenanceComplete ||
    build.commandPath !== "github.com/go-acme/lego/v5" ||
    build.mainPath !== "github.com/go-acme/lego/v5" ||
    build.goos !== platform.os ||
    build.goarch !== platform.architecture ||
    !build.vcsModifiedKnown ||
    !build.vcsModifiedValid ||
    build.vcsModified
  ) {
    throw new RuntimeRequestError("invalid_response", 0);
  }
  return {
    canonicalPath: value.canonicalPath,
    version: value.version,
    commit: value.commit,
    versionOutput: value.versionOutput,
    platform,
    metadata: decodeMetadata(value.metadata),
    build,
    sha256: value.sha256,
  };
}

function decodeCompatibility(value: unknown): RuntimeCompatibility {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, ["state", "code", "summary"], ["manifestId"]) ||
    typeof value.state !== "string" ||
    !selectedStates.has(value.state as CompatibilityState) ||
    !compatibilityCodes.has(value.code as RuntimeCompatibilityCode) ||
    !boundedString(value.summary, 1024) ||
    (value.manifestId !== undefined &&
      (typeof value.manifestId !== "string" ||
        !manifestIdPattern.test(value.manifestId))) ||
    (value.state === "supported" &&
      (value.manifestId === undefined || value.code !== "compatible")) ||
    (value.state === "unverified" && value.code !== "unknown_identity") ||
    (value.state === "incompatible" &&
      (value.code === "compatible" || value.code === "unknown_identity"))
  ) {
    throw new RuntimeRequestError("invalid_response", 0);
  }
  return {
    state: value.state as CompatibilityState,
    code: value.code as RuntimeCompatibilityCode,
    summary: value.summary,
    ...(value.manifestId === undefined ? {} : { manifestId: value.manifestId }),
  };
}

function decodeDiagnostic(
  value: unknown,
  state: RuntimeDiagnosticState,
): RuntimeDiagnostic {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, ["code", "message"]) ||
    !diagnosticCodes.has(value.code as RuntimeDiagnosticCode) ||
    !boundedString(value.message, 1024)
  ) {
    throw new RuntimeRequestError("invalid_response", 0);
  }
  const code = value.code as RuntimeDiagnosticCode;
  const expectedState: RuntimeDiagnosticState =
    code === "path_unavailable"
      ? "missing"
      : code === "executable_replaced"
        ? "changed"
        : code === "probe_timeout" || code === "inspection_timeout"
          ? "timed_out"
          : code === "malformed_version_output" ||
              code === "probe_output_limit" ||
              code === "probe_failed" ||
              code === "probe_canceled" ||
              code === "inspection_canceled" ||
              code === "build_identity_mismatch"
            ? "malformed_output"
            : "unsafe";
  if (state !== expectedState) {
    throw new RuntimeRequestError("invalid_response", 0);
  }
  return { code, message: value.message };
}

function decodeSnapshot(value: unknown): RuntimeSnapshot {
  if (!isRecord(value) || typeof value.state !== "string") {
    throw new RuntimeRequestError("invalid_response", 0);
  }
  if (value.state === "unselected") {
    if (!hasExactKeys(value, ["state"])) {
      throw new RuntimeRequestError("invalid_response", 0);
    }
    return { state: "unselected" };
  }
  if (selectedStates.has(value.state as CompatibilityState)) {
    if (!hasExactKeys(value, ["state", "runtime", "compatibility"])) {
      throw new RuntimeRequestError("invalid_response", 0);
    }
    const compatibility = decodeCompatibility(value.compatibility);
    if (compatibility.state !== value.state) {
      throw new RuntimeRequestError("invalid_response", 0);
    }
    return {
      state: value.state as CompatibilityState,
      runtime: decodeEvidence(value.runtime),
      compatibility,
    };
  }
  if (diagnosticStates.has(value.state as RuntimeDiagnosticState)) {
    if (!hasExactKeys(value, ["state", "path", "diagnostic"], ["runtime"])) {
      throw new RuntimeRequestError("invalid_response", 0);
    }
    if (
      !boundedString(value.path, MAX_RUNTIME_PATH_LENGTH) ||
      runtimePathError(value.path) !== undefined
    ) {
      throw new RuntimeRequestError("invalid_response", 0);
    }
    return {
      state: value.state as RuntimeDiagnosticState,
      path: value.path,
      diagnostic: decodeDiagnostic(
        value.diagnostic,
        value.state as RuntimeDiagnosticState,
      ),
      ...(value.runtime === undefined
        ? {}
        : { runtime: decodeEvidence(value.runtime) }),
    };
  }
  throw new RuntimeRequestError("invalid_response", 0);
}

function decodeCandidate(value: unknown): RuntimeCandidate {
  if (!isRecord(value) || typeof value.state !== "string") {
    throw new RuntimeRequestError("invalid_response", 0);
  }
  if (value.state === "review_required") {
    if (
      !hasExactKeys(
        value,
        ["state", "candidate", "compatibility"],
        ["reviewedEvidenceSha256"],
      ) ||
      (value.reviewedEvidenceSha256 !== undefined &&
        (typeof value.reviewedEvidenceSha256 !== "string" ||
          !/^[a-f0-9]{64}$/.test(value.reviewedEvidenceSha256)))
    ) {
      throw new RuntimeRequestError("invalid_response", 0);
    }
    const compatibility = decodeCompatibility(value.compatibility);
    if (
      compatibility.state === "supported" &&
      value.reviewedEvidenceSha256 === undefined
    ) {
      throw new RuntimeRequestError("invalid_response", 0);
    }
    return {
      state: "review_required",
      candidate: decodeEvidence(value.candidate),
      compatibility,
      ...(value.reviewedEvidenceSha256 === undefined
        ? {}
        : { reviewedEvidenceSha256: value.reviewedEvidenceSha256 }),
    };
  }
  if (candidateDiagnosticStates.has(value.state)) {
    if (
      !hasExactKeys(value, ["state", "path", "diagnostic"]) ||
      !boundedString(value.path, MAX_RUNTIME_PATH_LENGTH) ||
      runtimePathError(value.path) !== undefined
    ) {
      throw new RuntimeRequestError("invalid_response", 0);
    }
    return {
      state: value.state as RuntimeCandidate["state"] &
        Exclude<RuntimeDiagnosticState, "changed">,
      path: value.path,
      diagnostic: decodeDiagnostic(
        value.diagnostic,
        value.state as RuntimeDiagnosticState,
      ),
    };
  }
  throw new RuntimeRequestError("invalid_response", 0);
}

function isJSONContentType(value: string): boolean {
  return value.split(";", 1)[0]?.trim().toLowerCase() === "application/json";
}

async function readJSON(response: Response): Promise<unknown> {
  if (!isJSONContentType(response.headers.get("content-type") ?? "")) {
    throw new RuntimeRequestError("invalid_response", response.status);
  }
  try {
    return await response.json();
  } catch {
    throw new RuntimeRequestError("invalid_response", response.status);
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

function fallbackCode(status: number): RuntimeErrorCode {
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
      return "runtime_changed";
    case 503:
      return "service_unavailable";
    default:
      return "invalid_response";
  }
}

async function responseError(response: Response): Promise<RuntimeRequestError> {
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
        boundedString(value.error.message, 1024) &&
        knownErrorCodes.has(value.error.code as RuntimeErrorCode)
      ) {
        code = value.error.code as RuntimeErrorCode;
      }
    } catch {
      // Error bodies are deliberately neither retained nor rendered.
    }
  }
  return new RuntimeRequestError(code, response.status);
}

export function runtimePathError(path: string): string | undefined {
  if (path.length === 0) {
    return "Enter the absolute path to the lego executable on this host.";
  }
  if (new TextEncoder().encode(path).length > MAX_RUNTIME_PATH_LENGTH) {
    return `The path must be ${MAX_RUNTIME_PATH_LENGTH.toLocaleString("en-US")} UTF-8 bytes or fewer.`;
  }
  if (!path.startsWith("/")) {
    return "Enter an absolute Linux host path beginning with /.";
  }
  if (/[\0\r\n]/.test(path)) {
    return "The path cannot contain line breaks or null characters.";
  }
  return undefined;
}

function validatePath(path: string): void {
  if (runtimePathError(path)) {
    throw new RuntimeRequestError("invalid_request", 0);
  }
}

export function createRuntimeClient(
  options: RuntimeClientOptions = {},
): RuntimeClient {
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
    mutation = false,
  ): Promise<unknown> {
    const headers = new Headers(init.headers);
    headers.set("Accept", "application/json");
    if (mutation) {
      const csrf = readCookie(CSRF_COOKIE_NAME, readCookies());
      if (!csrf) {
        throw new RuntimeRequestError("invalid_response", 0);
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
      throw new RuntimeRequestError("network_failure", 0);
    }
    if (!response.ok) {
      throw await responseError(response);
    }
    return readJSON(response);
  }

  return {
    async getRuntime() {
      return decodeSnapshot(await send("/api/v1/runtime", { method: "GET" }));
    },
    async inspectCandidate(path: string) {
      validatePath(path);
      return decodeCandidate(
        await send(
          "/api/v1/runtime/candidates",
          { body: JSON.stringify({ path }), method: "POST" },
          true,
        ),
      );
    },
    async adoptCandidate(
      candidate: RuntimeEvidence,
      manifestId: string,
      reviewedEvidenceSha256: string,
    ) {
      validatePath(candidate.canonicalPath);
      if (
        !manifestIdPattern.test(manifestId) ||
        !/^[a-f0-9]{64}$/.test(reviewedEvidenceSha256)
      ) {
        throw new RuntimeRequestError("invalid_request", 0);
      }
      return decodeSnapshot(
        await send(
          "/api/v1/runtime",
          {
            body: JSON.stringify({
              path: candidate.canonicalPath,
              reviewedSha256: candidate.sha256,
              reviewedManifestId: manifestId,
              reviewedEvidenceSha256,
            }),
            method: "PUT",
          },
          true,
        ),
      );
    },
  };
}

export const browserRuntimeClient = createRuntimeClient();
