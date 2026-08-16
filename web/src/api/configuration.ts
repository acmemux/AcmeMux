import { CSRF_COOKIE_NAME, CSRF_HEADER_NAME } from "./session";

const MAX_PATH_BYTES = 4095;
const MAX_FIELDS = 1024;
const MAX_CHANGES = 128;
const MAX_DIAGNOSTICS = 256;
const MAX_SUMMARY_ITEMS = 256;
const MAX_TEXT_BYTES = 4096;
const MAX_SECRET_BYTES = 64 * 1024;

const revisionTokenPattern = /^[A-Za-z0-9_-]{43}$/;
const fieldIdPattern = /^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+$/;
const bindingIdPattern = /^[a-z][a-z0-9_]{0,63}$/;
const manifestIdPattern = /^[a-z0-9][a-z0-9._-]{0,127}$/;

export type ConfigurationState =
  "ready" | "unsupported" | "invalid" | "recovery_required";

export type ConfigurationSource = {
  baseRevisionToken: string;
  configurationPath: string;
  dotenvPaths: string[];
  runtimeManifestId: string;
};

export type ConfigurationCapabilities = {
  editing: boolean;
  execution: boolean;
};

export type ConfigurationBinding = {
  id: string;
  value: string;
};

type ProjectedFieldMetadata = {
  fieldId: string;
  bindings: ConfigurationBinding[];
  label: string;
  present: boolean;
  defaulted: boolean;
  presenceKnown: boolean;
};

export type ProjectedField =
  | {
      fieldId: string;
      bindings: ConfigurationBinding[];
      label: string;
      kind: "string";
      present: boolean;
      configured: true;
      defaulted: boolean;
      presenceKnown: boolean;
      value: string;
    }
  | {
      fieldId: string;
      bindings: ConfigurationBinding[];
      label: string;
      kind: "boolean";
      present: boolean;
      configured: true;
      defaulted: boolean;
      presenceKnown: boolean;
      value: boolean;
    }
  | {
      fieldId: string;
      bindings: ConfigurationBinding[];
      label: string;
      kind: "integer";
      present: boolean;
      configured: true;
      defaulted: boolean;
      presenceKnown: boolean;
      value: number;
    }
  | {
      fieldId: string;
      bindings: ConfigurationBinding[];
      label: string;
      kind: "string_list";
      present: boolean;
      configured: true;
      defaulted: boolean;
      presenceKnown: boolean;
      value: string[];
    }
  | (ProjectedFieldMetadata & {
      kind: "string" | "boolean" | "integer" | "string_list";
      configured: false;
    })
  | (ProjectedFieldMetadata & {
      kind: "secret";
      configured: boolean;
    });

export type ConfigurationDiagnosticCode =
  | "unsupported_ca"
  | "unsupported_provider"
  | "unsupported_challenge"
  | "unsupported_hooks"
  | "unsupported_output"
  | "unsupported_content"
  | "unknown_field"
  | "yaml_alias_unsupported"
  | "yaml_merge_unsupported"
  | "yaml_tag_unsupported"
  | "multiple_documents"
  | "duplicate_key"
  | "invalid_utf8"
  | "document_empty"
  | "document_malformed"
  | "document_too_large"
  | "document_too_complex"
  | "dotenv_malformed"
  | "dotenv_duplicate_key"
  | "dotenv_key_not_allowed"
  | "dotenv_expansion_not_allowed"
  | "schema_validation_failed"
  | "semantic_validation_failed"
  | "runtime_manifest_changed"
  | "source_changed"
  | "unsafe_path"
  | "synchronization_failed"
  | "replacement_interrupted"
  | "recovery_required";

export type ConfigurationDiagnostic = {
  code: ConfigurationDiagnosticCode;
  severity: "blocking" | "notice";
  role:
    | "configuration"
    | "dotenv"
    | "schema"
    | "semantic"
    | "filesystem"
    | "recovery";
  message: string;
  fieldId: string | null;
  bindings: ConfigurationBinding[];
  path: string | null;
  line: number | null;
  column: number | null;
};

export type RecoveryEvidence = {
  phase: "staging" | "prepared" | "replacing" | "finalizing";
  state: "unapplied" | "partial" | "applied" | "ambiguous";
  targets: Array<{
    role: "configuration" | "dotenv";
    path: string;
    state: "unstaged" | "unapplied" | "applied" | "ambiguous";
  }>;
};

export type RecoveryResolution =
  "discard_unapplied" | "finalize_applied" | "adopt_current";

type CurrentConfigurationSnapshot = {
  state: "ready" | "unsupported" | "invalid";
  source: ConfigurationSource;
  projection: ProjectedField[];
  diagnostics: ConfigurationDiagnostic[];
  capabilities: ConfigurationCapabilities;
};

export type ConfigurationSnapshot =
  | CurrentConfigurationSnapshot
  | {
      state: "recovery_required";
      source: ConfigurationSource;
      recovery: RecoveryEvidence;
      diagnostics: ConfigurationDiagnostic[];
      capabilities: { editing: false; execution: false };
    };

export type ConfigurationValue = string | boolean | number | string[];

export type ConfigurationChange =
  | {
      fieldId: string;
      bindings: ConfigurationBinding[];
      operation: "set";
      value: ConfigurationValue;
    }
  | {
      fieldId: string;
      bindings: ConfigurationBinding[];
      operation: "remove";
    };

export type SummaryValue =
  | { state: "absent" }
  | { state: "present_secret" }
  | { state: "present_unsupported" }
  | { state: "value"; value: ConfigurationValue };

export type ChangeSummary = {
  fieldId: string;
  bindings: ConfigurationBinding[];
  label: string;
  file: "configuration" | "dotenv";
  action:
    "added" | "changed" | "removed" | "secret_replaced" | "secret_removed";
  sensitive: boolean;
  before: SummaryValue;
  after: SummaryValue;
};

export type ConfigurationPreview =
  | { state: "unchanged"; baseRevisionToken: string }
  | {
      state: "invalid";
      baseRevisionToken: string;
      summary: ChangeSummary[];
      diagnostics: ConfigurationDiagnostic[];
    }
  | {
      state: "review_required";
      baseRevisionToken: string;
      reviewedPreviewToken: string;
      resultingState: "ready" | "unsupported";
      summary: ChangeSummary[];
      diagnostics: ConfigurationDiagnostic[];
      executionAllowed: boolean;
    };

export type ConfigurationErrorCode =
  | "authentication_required"
  | "request_not_allowed"
  | "invalid_request"
  | "configuration_changed"
  | "service_busy"
  | "service_unavailable"
  | "invalid_response"
  | "network_failure";

export class ConfigurationRequestError extends Error {
  readonly code: ConfigurationErrorCode;
  readonly status: number;

  constructor(code: ConfigurationErrorCode, status: number) {
    super(configurationErrorMessage(code));
    this.name = "ConfigurationRequestError";
    this.code = code;
    this.status = status;
  }
}

export interface ConfigurationClient {
  getConfiguration(): Promise<ConfigurationSnapshot>;
  previewChanges(
    baseRevisionToken: string,
    changes: ConfigurationChange[],
  ): Promise<ConfigurationPreview>;
  saveChanges(
    baseRevisionToken: string,
    changes: ConfigurationChange[],
    reviewedPreviewToken: string,
  ): Promise<ConfigurationSnapshot>;
  resolveRecovery(
    baseRevisionToken: string,
    resolution: RecoveryResolution,
  ): Promise<ConfigurationSnapshot>;
}

type ConfigurationClientOptions = {
  fetch?: typeof globalThis.fetch;
  readCookies?: () => string;
};

const diagnosticCodes = new Set<ConfigurationDiagnosticCode>([
  "unsupported_ca",
  "unsupported_provider",
  "unsupported_challenge",
  "unsupported_hooks",
  "unsupported_output",
  "unsupported_content",
  "unknown_field",
  "yaml_alias_unsupported",
  "yaml_merge_unsupported",
  "yaml_tag_unsupported",
  "multiple_documents",
  "duplicate_key",
  "invalid_utf8",
  "document_empty",
  "document_malformed",
  "document_too_large",
  "document_too_complex",
  "dotenv_malformed",
  "dotenv_duplicate_key",
  "dotenv_key_not_allowed",
  "dotenv_expansion_not_allowed",
  "schema_validation_failed",
  "semantic_validation_failed",
  "runtime_manifest_changed",
  "source_changed",
  "unsafe_path",
  "synchronization_failed",
  "replacement_interrupted",
  "recovery_required",
]);
const diagnosticRoles = new Set<ConfigurationDiagnostic["role"]>([
  "configuration",
  "dotenv",
  "schema",
  "semantic",
  "filesystem",
  "recovery",
]);
const knownErrorCodes = new Set<ConfigurationErrorCode>([
  "authentication_required",
  "request_not_allowed",
  "invalid_request",
  "configuration_changed",
  "service_busy",
  "service_unavailable",
]);

function configurationErrorMessage(code: ConfigurationErrorCode): string {
  switch (code) {
    case "authentication_required":
      return "The administrator session ended.";
    case "request_not_allowed":
      return "The protected configuration request was blocked.";
    case "invalid_request":
      return "The configuration request was invalid.";
    case "configuration_changed":
      return "The native configuration changed after review.";
    case "service_busy":
      return "Another native workspace action is in progress.";
    case "service_unavailable":
    case "network_failure":
      return "Configuration status is unavailable.";
    case "invalid_response":
      return "The configuration service returned an invalid response.";
  }
}

function invalidResponse(): never {
  throw new ConfigurationRequestError("invalid_response", 0);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasExactKeys(
  value: Record<string, unknown>,
  required: readonly string[],
  optional: readonly string[] = [],
): boolean {
  const allowed = new Set([...required, ...optional]);
  return (
    required.every((key) => Object.prototype.hasOwnProperty.call(value, key)) &&
    Object.keys(value).every((key) => allowed.has(key))
  );
}

function containsControlCharacter(value: string): boolean {
  return Array.from(value).some((character) => {
    const point = character.codePointAt(0) ?? 0;
    return point < 0x20 || point === 0x7f;
  });
}

function boundedText(
  value: unknown,
  maximum = MAX_TEXT_BYTES,
): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    new TextEncoder().encode(value).length <= maximum &&
    !containsControlCharacter(value)
  );
}

function validToken(value: unknown): value is string {
  return typeof value === "string" && revisionTokenPattern.test(value);
}

function validFieldId(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length <= 128 &&
    fieldIdPattern.test(value)
  );
}

function validBindings(value: unknown): value is ConfigurationBinding[] {
  return (
    Array.isArray(value) &&
    value.length <= 16 &&
    value.every(
      (binding) =>
        isRecord(binding) &&
        hasExactKeys(binding, ["id", "value"]) &&
        typeof binding.id === "string" &&
        bindingIdPattern.test(binding.id) &&
        boundedText(binding.value, 256),
    ) &&
    new Set(value.map((binding) => binding.id)).size === value.length
  );
}

function decodeBindings(value: unknown): ConfigurationBinding[] {
  if (!validBindings(value)) invalidResponse();
  return value.map(({ id, value: bindingValue }) => ({
    id,
    value: bindingValue,
  }));
}

function configurationIdentityKey(
  fieldId: string,
  bindings: ConfigurationBinding[],
): string {
  return JSON.stringify([
    fieldId,
    bindings.map(({ id, value }) => [id, value]),
  ]);
}

function validCanonicalAbsolutePath(value: unknown): value is string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    new TextEncoder().encode(value).length > MAX_PATH_BYTES ||
    !value.startsWith("/") ||
    containsControlCharacter(value)
  ) {
    return false;
  }
  if (value === "/") {
    return true;
  }
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

function decodeSource(value: unknown): ConfigurationSource {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      "baseRevisionToken",
      "configurationPath",
      "dotenvPaths",
      "runtimeManifestId",
    ])
  ) {
    invalidResponse();
  }
  const dotenvPaths = value.dotenvPaths;
  if (
    !validToken(value.baseRevisionToken) ||
    !validCanonicalAbsolutePath(value.configurationPath) ||
    !Array.isArray(dotenvPaths) ||
    dotenvPaths.length > 128 ||
    !dotenvPaths.every(validCanonicalAbsolutePath) ||
    new Set(dotenvPaths).size !== dotenvPaths.length ||
    !dotenvPaths.every(
      (path, index) => index === 0 || dotenvPaths[index - 1] < path,
    ) ||
    dotenvPaths.includes(value.configurationPath) ||
    typeof value.runtimeManifestId !== "string" ||
    !manifestIdPattern.test(value.runtimeManifestId)
  ) {
    invalidResponse();
  }
  return {
    baseRevisionToken: value.baseRevisionToken,
    configurationPath: value.configurationPath,
    dotenvPaths: [...dotenvPaths] as string[],
    runtimeManifestId: value.runtimeManifestId,
  };
}

function decodeCapabilities(value: unknown): ConfigurationCapabilities {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, ["editing", "execution"]) ||
    typeof value.editing !== "boolean" ||
    typeof value.execution !== "boolean"
  ) {
    invalidResponse();
  }
  return { editing: value.editing, execution: value.execution };
}

function decodeStringList(value: unknown): string[] {
  if (
    !Array.isArray(value) ||
    value.length > 256 ||
    !value.every((item) => boundedText(item))
  ) {
    invalidResponse();
  }
  return [...value] as string[];
}

function decodeProjectedField(value: unknown): ProjectedField {
  if (
    !isRecord(value) ||
    !hasExactKeys(
      value,
      [
        "fieldId",
        "bindings",
        "label",
        "kind",
        "present",
        "configured",
        "defaulted",
        "presenceKnown",
      ],
      ["value"],
    ) ||
    !validFieldId(value.fieldId) ||
    !boundedText(value.label, 256) ||
    typeof value.kind !== "string" ||
    typeof value.present !== "boolean" ||
    typeof value.configured !== "boolean" ||
    typeof value.defaulted !== "boolean" ||
    typeof value.presenceKnown !== "boolean" ||
    (value.present && !value.presenceKnown) ||
    (value.defaulted && (!value.configured || value.present))
  ) {
    invalidResponse();
  }
  const bindings = decodeBindings(value.bindings);
  const metadata = {
    fieldId: value.fieldId,
    bindings,
    label: value.label,
    present: value.present,
    configured: value.configured,
    defaulted: value.defaulted,
    presenceKnown: value.presenceKnown,
  };
  if (value.kind === "secret") {
    if (Object.prototype.hasOwnProperty.call(value, "value")) {
      invalidResponse();
    }
    return { ...metadata, kind: "secret" };
  }
  if (
    value.kind !== "string" &&
    value.kind !== "boolean" &&
    value.kind !== "integer" &&
    value.kind !== "string_list"
  ) {
    invalidResponse();
  }
  if (!value.configured) {
    if (Object.prototype.hasOwnProperty.call(value, "value")) {
      invalidResponse();
    }
    return { ...metadata, configured: false, kind: value.kind };
  }
  switch (value.kind) {
    case "string":
      if (!boundedText(value.value)) invalidResponse();
      return {
        ...metadata,
        configured: true,
        kind: "string",
        value: value.value,
      };
    case "boolean":
      if (typeof value.value !== "boolean") invalidResponse();
      return {
        ...metadata,
        configured: true,
        kind: "boolean",
        value: value.value,
      };
    case "integer":
      if (!Number.isSafeInteger(value.value)) invalidResponse();
      return {
        ...metadata,
        configured: true,
        kind: "integer",
        value: value.value as number,
      };
    case "string_list":
      return {
        ...metadata,
        configured: true,
        kind: "string_list",
        value: decodeStringList(value.value),
      };
  }
}

function decodeProjection(value: unknown): ProjectedField[] {
  if (!Array.isArray(value) || value.length > MAX_FIELDS) {
    invalidResponse();
  }
  const fields = value.map(decodeProjectedField);
  const identities = fields.map((field) =>
    configurationIdentityKey(field.fieldId, field.bindings),
  );
  if (
    new Set(identities).size !== fields.length ||
    !identities.every(
      (identity, index) => index === 0 || identities[index - 1]! < identity,
    )
  ) {
    invalidResponse();
  }
  return fields;
}

function optionalLocation(value: unknown): number | null {
  if (value === null) return null;
  if (
    !Number.isSafeInteger(value) ||
    Number(value) < 1 ||
    Number(value) > 10_000_000
  ) {
    invalidResponse();
  }
  return value as number;
}

function decodeDiagnostic(value: unknown): ConfigurationDiagnostic {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      "code",
      "severity",
      "role",
      "message",
      "fieldId",
      "bindings",
      "path",
      "line",
      "column",
    ]) ||
    !diagnosticCodes.has(value.code as ConfigurationDiagnosticCode) ||
    (value.severity !== "blocking" && value.severity !== "notice") ||
    !diagnosticRoles.has(value.role as ConfigurationDiagnostic["role"]) ||
    !boundedText(value.message, 1024) ||
    (value.fieldId !== null && !validFieldId(value.fieldId)) ||
    (value.path !== null && !validCanonicalAbsolutePath(value.path))
  ) {
    invalidResponse();
  }
  const bindings = decodeBindings(value.bindings);
  if (value.fieldId === null && bindings.length !== 0) {
    invalidResponse();
  }
  const line = optionalLocation(value.line);
  const column = optionalLocation(value.column);
  if ((line === null) !== (column === null)) {
    invalidResponse();
  }
  return {
    code: value.code as ConfigurationDiagnosticCode,
    severity: value.severity,
    role: value.role as ConfigurationDiagnostic["role"],
    message: value.message,
    fieldId: value.fieldId as string | null,
    bindings,
    path: value.path as string | null,
    line,
    column,
  };
}

function decodeDiagnostics(value: unknown): ConfigurationDiagnostic[] {
  if (!Array.isArray(value) || value.length > MAX_DIAGNOSTICS) {
    invalidResponse();
  }
  return value.map(decodeDiagnostic);
}

function decodeRecovery(value: unknown): RecoveryEvidence {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, ["phase", "state", "targets"]) ||
    (value.phase !== "staging" &&
      value.phase !== "prepared" &&
      value.phase !== "replacing" &&
      value.phase !== "finalizing") ||
    (value.state !== "unapplied" &&
      value.state !== "partial" &&
      value.state !== "applied" &&
      value.state !== "ambiguous") ||
    !Array.isArray(value.targets) ||
    value.targets.length === 0 ||
    value.targets.length > 129
  ) {
    invalidResponse();
  }
  const targets = value.targets.map((target) => {
    if (
      !isRecord(target) ||
      !hasExactKeys(target, ["role", "path", "state"]) ||
      (target.role !== "configuration" && target.role !== "dotenv") ||
      !validCanonicalAbsolutePath(target.path) ||
      (target.state !== "unstaged" &&
        target.state !== "unapplied" &&
        target.state !== "applied" &&
        target.state !== "ambiguous")
    ) {
      invalidResponse();
    }
    return {
      role: target.role,
      path: target.path,
      state: target.state,
    } as RecoveryEvidence["targets"][number];
  });
  const targetStates = targets.map((target) => target.state);
  const coherentState =
    (value.state === "unapplied" &&
      targetStates.every(
        (state) => state === "unstaged" || state === "unapplied",
      )) ||
    (value.state === "partial" &&
      targetStates.some((state) => state === "applied") &&
      targetStates.some(
        (state) => state === "unstaged" || state === "unapplied",
      ) &&
      !targetStates.includes("ambiguous")) ||
    (value.state === "applied" &&
      targetStates.every((state) => state === "applied")) ||
    (value.state === "ambiguous" &&
      targetStates.some((state) => state === "ambiguous"));
  if (
    new Set(targets.map((target) => target.path)).size !== targets.length ||
    !coherentState
  ) {
    invalidResponse();
  }
  return { phase: value.phase, state: value.state, targets };
}

function decodeSnapshot(value: unknown): ConfigurationSnapshot {
  if (!isRecord(value) || typeof value.state !== "string") {
    invalidResponse();
  }
  if (value.state === "recovery_required") {
    if (
      !hasExactKeys(value, [
        "state",
        "source",
        "recovery",
        "diagnostics",
        "capabilities",
      ])
    ) {
      invalidResponse();
    }
    const capabilities = decodeCapabilities(value.capabilities);
    const diagnostics = decodeDiagnostics(value.diagnostics);
    if (
      capabilities.editing ||
      capabilities.execution ||
      !diagnostics.some(
        (diagnostic) =>
          diagnostic.severity === "blocking" &&
          diagnostic.code === "recovery_required",
      )
    ) {
      invalidResponse();
    }
    return {
      state: "recovery_required",
      source: decodeSource(value.source),
      recovery: decodeRecovery(value.recovery),
      diagnostics,
      capabilities: { editing: false, execution: false },
    };
  }
  if (
    value.state !== "ready" &&
    value.state !== "unsupported" &&
    value.state !== "invalid"
  ) {
    invalidResponse();
  }
  if (
    !hasExactKeys(value, [
      "state",
      "source",
      "projection",
      "diagnostics",
      "capabilities",
    ])
  ) {
    invalidResponse();
  }
  const capabilities = decodeCapabilities(value.capabilities);
  const diagnostics = decodeDiagnostics(value.diagnostics);
  const blocking = diagnostics.some(
    (diagnostic) => diagnostic.severity === "blocking",
  );
  if (
    (value.state === "ready" &&
      (!capabilities.editing || !capabilities.execution || blocking)) ||
    (value.state === "unsupported" && (capabilities.execution || !blocking)) ||
    (value.state === "invalid" &&
      (capabilities.editing || capabilities.execution || !blocking))
  ) {
    invalidResponse();
  }
  return {
    state: value.state,
    source: decodeSource(value.source),
    projection: decodeProjection(value.projection),
    diagnostics,
    capabilities,
  };
}

function decodeSummaryValue(value: unknown): SummaryValue {
  if (!isRecord(value) || typeof value.state !== "string") {
    invalidResponse();
  }
  if (
    value.state === "absent" ||
    value.state === "present_secret" ||
    value.state === "present_unsupported"
  ) {
    if (!hasExactKeys(value, ["state"])) invalidResponse();
    return { state: value.state };
  }
  if (
    value.state !== "value" ||
    !hasExactKeys(value, ["state", "value"]) ||
    !validPublicValue(value.value)
  ) {
    invalidResponse();
  }
  return {
    state: "value",
    value: Array.isArray(value.value) ? [...value.value] : value.value,
  };
}

function validPublicValue(value: unknown): value is ConfigurationValue {
  return (
    boundedText(value) ||
    typeof value === "boolean" ||
    Number.isSafeInteger(value) ||
    (Array.isArray(value) &&
      value.length <= 256 &&
      value.every((item) => boundedText(item)))
  );
}

function decodeSummary(value: unknown): ChangeSummary[] {
  if (!Array.isArray(value) || value.length > MAX_SUMMARY_ITEMS) {
    invalidResponse();
  }
  const items = value.map((item) => {
    if (
      !isRecord(item) ||
      !hasExactKeys(item, [
        "fieldId",
        "bindings",
        "label",
        "file",
        "action",
        "sensitive",
        "before",
        "after",
      ]) ||
      !validFieldId(item.fieldId) ||
      !boundedText(item.label, 256) ||
      (item.file !== "configuration" && item.file !== "dotenv") ||
      (item.action !== "added" &&
        item.action !== "changed" &&
        item.action !== "removed" &&
        item.action !== "secret_replaced" &&
        item.action !== "secret_removed") ||
      typeof item.sensitive !== "boolean"
    ) {
      invalidResponse();
    }
    const bindings = decodeBindings(item.bindings);
    const before = decodeSummaryValue(item.before);
    const after = decodeSummaryValue(item.after);
    const secretShape =
      item.sensitive &&
      before.state !== "value" &&
      after.state !== "value" &&
      (item.action === "secret_replaced" || item.action === "secret_removed");
    const publicShape =
      !item.sensitive &&
      item.action !== "secret_replaced" &&
      item.action !== "secret_removed" &&
      before.state !== "present_secret" &&
      after.state !== "present_secret";
    if (!secretShape && !publicShape) invalidResponse();
    if (
      (item.action === "added" &&
        (before.state !== "absent" || after.state !== "value")) ||
      (item.action === "changed" &&
        ((before.state !== "value" && before.state !== "present_unsupported") ||
          after.state !== "value")) ||
      (item.action === "removed" &&
        ((before.state !== "value" && before.state !== "present_unsupported") ||
          after.state !== "absent")) ||
      (item.action === "secret_replaced" && after.state !== "present_secret") ||
      (item.action === "secret_removed" &&
        (before.state !== "present_secret" || after.state !== "absent"))
    ) {
      invalidResponse();
    }
    return {
      fieldId: item.fieldId,
      bindings,
      label: item.label,
      file: item.file,
      action: item.action,
      sensitive: item.sensitive,
      before,
      after,
    } as ChangeSummary;
  });
  if (
    new Set(
      items.map((item) =>
        configurationIdentityKey(item.fieldId, item.bindings),
      ),
    ).size !== items.length
  ) {
    invalidResponse();
  }
  return items;
}

function decodePreview(value: unknown): ConfigurationPreview {
  if (!isRecord(value) || typeof value.state !== "string") {
    invalidResponse();
  }
  if (value.state === "unchanged") {
    if (
      !hasExactKeys(value, ["state", "baseRevisionToken"]) ||
      !validToken(value.baseRevisionToken)
    ) {
      invalidResponse();
    }
    return { state: "unchanged", baseRevisionToken: value.baseRevisionToken };
  }
  if (value.state === "invalid") {
    if (
      !hasExactKeys(value, [
        "state",
        "baseRevisionToken",
        "summary",
        "diagnostics",
      ]) ||
      !validToken(value.baseRevisionToken)
    ) {
      invalidResponse();
    }
    const diagnostics = decodeDiagnostics(value.diagnostics);
    if (!diagnostics.some((diagnostic) => diagnostic.severity === "blocking")) {
      invalidResponse();
    }
    return {
      state: "invalid",
      baseRevisionToken: value.baseRevisionToken,
      summary: decodeSummary(value.summary),
      diagnostics,
    };
  }
  if (
    value.state !== "review_required" ||
    !hasExactKeys(value, [
      "state",
      "baseRevisionToken",
      "reviewedPreviewToken",
      "resultingState",
      "summary",
      "diagnostics",
      "executionAllowed",
    ]) ||
    !validToken(value.baseRevisionToken) ||
    !validToken(value.reviewedPreviewToken) ||
    (value.resultingState !== "ready" &&
      value.resultingState !== "unsupported") ||
    typeof value.executionAllowed !== "boolean" ||
    value.executionAllowed !== (value.resultingState === "ready")
  ) {
    invalidResponse();
  }
  const summary = decodeSummary(value.summary);
  const diagnostics = decodeDiagnostics(value.diagnostics);
  if (
    summary.length === 0 ||
    (value.resultingState === "ready" &&
      diagnostics.some((diagnostic) => diagnostic.severity === "blocking")) ||
    (value.resultingState === "unsupported" &&
      !diagnostics.some((diagnostic) => diagnostic.severity === "blocking"))
  ) {
    invalidResponse();
  }
  return {
    state: "review_required",
    baseRevisionToken: value.baseRevisionToken,
    reviewedPreviewToken: value.reviewedPreviewToken,
    resultingState: value.resultingState,
    summary,
    diagnostics,
    executionAllowed: value.executionAllowed,
  };
}

function validChangeValue(value: unknown): value is ConfigurationValue {
  if (typeof value === "string") {
    return (
      value.length > 0 &&
      new TextEncoder().encode(value).length <= MAX_SECRET_BYTES &&
      !value.includes("\0")
    );
  }
  if (typeof value === "boolean") return true;
  if (typeof value === "number") return Number.isSafeInteger(value);
  return (
    Array.isArray(value) &&
    value.length <= 256 &&
    value.every((item) => boundedText(item))
  );
}

function validateChanges(changes: ConfigurationChange[]): void {
  if (
    !Array.isArray(changes) ||
    changes.length === 0 ||
    changes.length > MAX_CHANGES
  ) {
    throw new ConfigurationRequestError("invalid_request", 0);
  }
  const identities = new Set<string>();
  for (const raw of changes as unknown[]) {
    if (
      !isRecord(raw) ||
      !validFieldId(raw.fieldId) ||
      !validBindings(raw.bindings) ||
      typeof raw.operation !== "string"
    ) {
      throw new ConfigurationRequestError("invalid_request", 0);
    }
    const identity = configurationIdentityKey(raw.fieldId, raw.bindings);
    if (identities.has(identity)) {
      throw new ConfigurationRequestError("invalid_request", 0);
    }
    identities.add(identity);
    switch (raw.operation) {
      case "set":
        if (
          !hasExactKeys(raw, ["fieldId", "bindings", "operation", "value"]) ||
          !validChangeValue(raw.value)
        ) {
          throw new ConfigurationRequestError("invalid_request", 0);
        }
        break;
      case "remove":
        if (!hasExactKeys(raw, ["fieldId", "bindings", "operation"])) {
          throw new ConfigurationRequestError("invalid_request", 0);
        }
        break;
      default:
        throw new ConfigurationRequestError("invalid_request", 0);
    }
  }
}

function isJSONContentType(value: string): boolean {
  return value.split(";", 1)[0]?.trim().toLowerCase() === "application/json";
}

async function readJSON(response: Response): Promise<unknown> {
  if (!isJSONContentType(response.headers.get("content-type") ?? "")) {
    throw new ConfigurationRequestError("invalid_response", response.status);
  }
  try {
    return await response.json();
  } catch {
    throw new ConfigurationRequestError("invalid_response", response.status);
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

function fallbackCode(status: number): ConfigurationErrorCode {
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
      return "configuration_changed";
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
): Promise<ConfigurationRequestError> {
  if (response.status === 401) {
    return new ConfigurationRequestError("authentication_required", 401);
  }
  if (response.status === 403 || response.status === 421) {
    return new ConfigurationRequestError(
      "request_not_allowed",
      response.status,
    );
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
        boundedText(value.error.message, 1024) &&
        knownErrorCodes.has(value.error.code as ConfigurationErrorCode)
      ) {
        const presented = value.error.code as ConfigurationErrorCode;
        if (
          presented !== "authentication_required" &&
          presented !== "request_not_allowed"
        ) {
          code = presented;
        }
      }
    } catch {
      // Error bodies are deliberately not retained or reflected.
    }
  }
  return new ConfigurationRequestError(code, response.status);
}

export function createConfigurationClient(
  options: ConfigurationClientOptions = {},
): ConfigurationClient {
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
        throw new ConfigurationRequestError("authentication_required", 401);
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
      throw new ConfigurationRequestError("network_failure", 0);
    }
    if (!response.ok) {
      throw await responseError(response);
    }
    return readJSON(response);
  }

  return {
    async getConfiguration() {
      return decodeSnapshot(
        await send("/api/v1/configuration", { method: "GET" }),
      );
    },
    async previewChanges(baseRevisionToken, changes) {
      if (!validToken(baseRevisionToken)) {
        throw new ConfigurationRequestError("invalid_request", 0);
      }
      validateChanges(changes);
      const preview = decodePreview(
        await send(
          "/api/v1/configuration/previews",
          {
            body: JSON.stringify({ baseRevisionToken, changes }),
            method: "POST",
          },
          true,
        ),
      );
      if (preview.baseRevisionToken !== baseRevisionToken) {
        invalidResponse();
      }
      return preview;
    },
    async saveChanges(baseRevisionToken, changes, reviewedPreviewToken) {
      if (!validToken(baseRevisionToken) || !validToken(reviewedPreviewToken)) {
        throw new ConfigurationRequestError("invalid_request", 0);
      }
      validateChanges(changes);
      return decodeSnapshot(
        await send(
          "/api/v1/configuration",
          {
            body: JSON.stringify({
              baseRevisionToken,
              changes,
              reviewedPreviewToken,
            }),
            method: "PUT",
          },
          true,
        ),
      );
    },
    async resolveRecovery(baseRevisionToken, resolution) {
      if (
        !validToken(baseRevisionToken) ||
        (resolution !== "discard_unapplied" &&
          resolution !== "finalize_applied" &&
          resolution !== "adopt_current")
      ) {
        throw new ConfigurationRequestError("invalid_request", 0);
      }
      return decodeSnapshot(
        await send(
          "/api/v1/configuration/recovery",
          {
            body: JSON.stringify({ baseRevisionToken, resolution }),
            method: "PUT",
          },
          true,
        ),
      );
    },
  };
}

export const browserConfigurationClient = createConfigurationClient();
